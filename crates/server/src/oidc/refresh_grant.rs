//! `grant_type=refresh_token`: rotation with family reuse detection and
//! optional down-scoping (RFC 6749 §6). The new refresh token keeps the
//! grant's original scopes; only the access token is narrowed.

use std::{collections::HashMap, net::IpAddr};

use entity::{applications, enums::NotifyEvent, refresh_tokens, users};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};

use super::{
    error::{ErrorCode, OAuthError, OAuthResult},
    scope,
    token::{active_user, load_app},
};
use crate::{
    app::AppState,
    audit, notify,
    tenancy::Tenant,
    tokens::{
        self, Delegated, Refresh, TokenSet,
        refresh::{self, State},
    },
};

fn invalid_scope(msg: &str) -> OAuthError {
    OAuthError::new(ErrorCode::InvalidScope, msg)
}

/// Narrows `(oidc, resource values)` of the original grant to what `raw`
/// asks for. `resource_prefix_ok` says whether the requested resource is the
/// grant's resource.
fn narrow(
    original_oidc: &[String],
    original_values: &[String],
    requested: &scope::RequestedScopes,
    resource_prefix_ok: bool,
) -> OAuthResult<(Vec<String>, Option<Vec<String>>)> {
    if !requested.oidc.iter().all(|s| original_oidc.contains(s)) {
        return Err(invalid_scope("scope exceeds the original grant"));
    }
    let values = match &requested.resource {
        None => None,
        Some(_) if !resource_prefix_ok => {
            return Err(invalid_scope("scope exceeds the original grant"));
        }
        Some((_, values)) if values.iter().any(|v| v == scope::DEFAULT) => {
            Some(original_values.to_vec())
        }
        Some((_, values)) => {
            if !values.iter().all(|v| original_values.contains(v)) {
                return Err(invalid_scope("scope exceeds the original grant"));
            }
            Some(values.clone())
        }
    };
    Ok((requested.oidc.clone(), values))
}

pub async fn grant(
    state: &AppState,
    tenant: &Tenant,
    ip: Option<IpAddr>,
    client: &applications::Model,
    params: &HashMap<String, String>,
) -> OAuthResult<TokenSet> {
    let conn = &state.db;
    let presented = params
        .get("refresh_token")
        .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
    let row = refresh::find(conn, tenant.id, presented)
        .await?
        .ok_or_else(|| OAuthError::invalid_grant("unknown refresh token"))?;
    if row.application_id != client.id {
        return Err(OAuthError::invalid_grant(
            "the refresh token was issued to another client",
        ));
    }
    let now = chrono::Utc::now().fixed_offset();
    match refresh::state(&row, now) {
        State::Active => {}
        State::Reused => return Err(reuse(state, tenant, conn, &row, client, ip).await?),
        State::Revoked => return Err(OAuthError::invalid_grant("refresh token revoked")),
        State::Expired => return Err(OAuthError::invalid_grant("refresh token expired")),
    }
    let user = active_user(conn, tenant.id, row.user_id).await?;
    let original_resource = load_app(conn, row.resource_application_id).await?;
    let (original_oidc, mut original_values) = scope::split_stored(&row.scopes);
    // Scopes the resource has since stopped exposing are never re-minted
    // (deleting a scope also revokes the families holding it; this keeps
    // the guarantee even for a family that slipped past that).
    if let Some(resource) = &original_resource {
        let exposed = scope::exposed_values(conn, resource.id).await?;
        original_values.retain(|v| exposed.contains(v));
    }

    let (oidc, resource, values) = match params.get("scope") {
        None => (original_oidc, original_resource, original_values),
        Some(raw) => {
            let requested = scope::parse(raw).map_err(|m| invalid_scope(&m))?;
            let prefix_ok = match (&requested.resource, &original_resource) {
                (Some((prefix, _)), Some(res)) => scope::find_resource(conn, tenant.id, prefix)
                    .await?
                    .is_some_and(|found| found.id == res.id),
                _ => false,
            };
            let (oidc, values) = narrow(&original_oidc, &original_values, &requested, prefix_ok)?;
            match values {
                Some(values) => (oidc, original_resource, values),
                None => (oidc, None, Vec::new()),
            }
        }
    };
    // Only now: a request rejected above (bad scope, disabled user) must not
    // burn the token. Rotation and issuance share ONE transaction: a
    // concurrent redemption of the same token blocks on its row lock until
    // we commit, then sees it rotated and revokes the family — including the
    // token we just issued.
    let txn = conn.begin().await?;
    if !refresh::mark_rotated(&txn, row.id).await? {
        let err = reuse(state, tenant, &txn, &row, client, ip).await?;
        txn.commit().await?;
        return Err(err);
    }

    let issuer = state.config.issuer(&tenant.slug);
    let set = tokens::issue_delegated(
        &txn,
        &state.config.master_key,
        Delegated {
            tenant,
            issuer: &issuer,
            client,
            user: &user,
            session_id: row.session_id,
            amr: &row.amr,
            auth_time: row.auth_time,
            nonce: None,
            oidc_scopes: &oidc,
            resource: resource.as_ref(),
            resource_scopes: &values,
            authorization_code_id: row.authorization_code_id,
            refresh: Some(Refresh {
                family_id: row.family_id,
                expires_at: row.expires_at,
                scopes: row.scopes.clone(),
                resource_app_id: row.resource_application_id,
            }),
        },
    )
    .await?;
    txn.commit().await?;
    Ok(set)
}

/// Revokes the family, audits the replay and warns the user (the token may
/// have been stolen).
async fn reuse(
    state: &AppState,
    tenant: &Tenant,
    conn: &impl sea_orm::ConnectionTrait,
    row: &refresh_tokens::Model,
    client: &applications::Model,
    ip: Option<IpAddr>,
) -> OAuthResult<OAuthError> {
    tracing::warn!(family_id = %row.family_id, "refresh token reuse; revoking the family");
    refresh::revoke_family(conn, row.family_id).await?;
    let details = serde_json::json!({ "family_id": row.family_id });
    audit::token_replay(
        conn,
        audit::EventType::TokenRefreshReuse,
        row.tenant_id,
        row.application_id,
        row.user_id,
        ip,
        details,
    )
    .await?;
    let user = users::Entity::find_by_id(row.user_id)
        .filter(users::Column::TenantId.eq(row.tenant_id))
        .one(conn)
        .await
        .map_err(anyhow::Error::from)?;
    if let Some(user) = user {
        let facts = [("Application", client.display_name.clone())];
        notify::event(
            conn,
            &state.config,
            tenant,
            &user,
            NotifyEvent::TokenReuse,
            &facts,
        )
        .await?;
    }
    Ok(OAuthError::invalid_grant(
        "refresh token already used; the grant was revoked",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn down_scoping_rules() {
        let oidc = s(&["openid", "offline_access"]);
        let values = s(&["read", "write"]);
        let req = scope::parse("openid api://x/read").unwrap();
        assert_eq!(
            narrow(&oidc, &values, &req, true).unwrap(),
            (s(&["openid"]), Some(s(&["read"])))
        );
        let req = scope::parse("api://x/.default").unwrap();
        assert_eq!(
            narrow(&oidc, &values, &req, true).unwrap().1,
            Some(values.clone())
        );
        let req = scope::parse("openid").unwrap();
        assert_eq!(
            narrow(&oidc, &values, &req, true).unwrap(),
            (s(&["openid"]), None)
        );
        for bad in ["email", "api://x/delete"] {
            let req = scope::parse(bad).unwrap();
            assert!(narrow(&oidc, &values, &req, true).is_err(), "{bad}");
        }
        // Another resource than the grant's.
        let req = scope::parse("api://other/read").unwrap();
        assert!(narrow(&oidc, &values, &req, false).is_err());
    }
}
