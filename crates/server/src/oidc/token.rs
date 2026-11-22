//! `POST /oauth2/token`: `authorization_code`, `refresh_token`,
//! `client_credentials` and the device code grant (`device_grant`). Errors
//! per RFC 6749 §5.2, always `no-store`.

use std::{collections::HashMap, net::IpAddr};

use anyhow::Context;
use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::Duration;
use entity::{applications, authorization_codes, enums::ClientType, users};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, TransactionTrait};
use uuid::Uuid;

use super::{
    assignment, client_auth, device_grant,
    error::{ErrorCode, OAuthError, OAuthResult},
    form_params, pkce, refresh_grant, scope,
};
use crate::{
    app::AppState,
    audit,
    authn::ip::ClientIp,
    backchannel, cors, metrics,
    tenancy::Tenant,
    tokens::{self, Delegated, Refresh, TokenSet},
};

pub async fn token(
    State(state): State<AppState>,
    tenant: Tenant,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let response = match handle(&state, &tenant, ip, &headers, &body).await {
        Ok((set, grant)) => {
            metrics::token_issued(grant, tokens::format_label(set.format));
            set.into_response()
        }
        Err(err) => {
            metrics::token_error(err.code.as_str());
            err.into_response()
        }
    };
    cors::for_client(&state, &tenant, &headers, &body, response).await
}

async fn handle(
    state: &AppState,
    tenant: &Tenant,
    ip: Option<IpAddr>,
    headers: &HeaderMap,
    body: &[u8],
) -> OAuthResult<(TokenSet, &'static str)> {
    let params = form_params(headers, body)?;
    let client = client_auth::authenticate(&state.db, tenant.id, headers, &params).await?;
    match params.get("grant_type").map(String::as_str) {
        Some("authorization_code") => Ok((
            authorization_code(state, tenant, ip, &client, &params).await?,
            "authorization_code",
        )),
        Some("refresh_token") => Ok((
            refresh_grant::grant(state, tenant, ip, &client, &params).await?,
            "refresh_token",
        )),
        Some("client_credentials") => Ok((
            client_credentials(state, tenant, &client, &params).await?,
            "client_credentials",
        )),
        Some(device_grant::GRANT_TYPE) => Ok((
            device_grant::grant(state, tenant, ip, headers, &client, &params).await?,
            "device_code",
        )),
        Some(_) => Err(OAuthError::new(
            ErrorCode::UnsupportedGrantType,
            "unsupported grant_type",
        )),
        None => Err(OAuthError::invalid_request("grant_type is required")),
    }
}

fn required<'a>(params: &'a HashMap<String, String>, key: &str) -> OAuthResult<&'a str> {
    params
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| OAuthError::invalid_request(format!("{key} is required")))
}

/// The user behind a delegated grant; disabled users get no more tokens.
pub(super) async fn active_user(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> OAuthResult<users::Model> {
    users::Entity::find_by_id(user_id)
        .filter(users::Column::TenantId.eq(tenant_id))
        .one(conn)
        .await
        .context("loading user")?
        .filter(|u| !u.disabled)
        .ok_or_else(inactive_user)
}

/// The `invalid_grant` for a user who is disabled or gone — also when
/// `backchannel::lock_user` finds that after [`active_user`] passed.
pub(super) fn inactive_user() -> OAuthError {
    OAuthError::invalid_grant("the user is disabled or no longer exists")
}

/// `invalid_grant` unless the user is assigned where required
/// ([`assignment`]).
pub(super) async fn ensure_assigned(
    conn: &impl ConnectionTrait,
    tenant: &Tenant,
    user: &users::Model,
    client: &applications::Model,
    resource: Option<&applications::Model>,
) -> OAuthResult<()> {
    if assignment::user_may_use(conn, tenant.id, user.id, client, resource).await? {
        Ok(())
    } else {
        Err(OAuthError::invalid_grant(assignment::NOT_ASSIGNED))
    }
}

pub(super) async fn load_app(
    conn: &impl ConnectionTrait,
    id: Option<Uuid>,
) -> OAuthResult<Option<applications::Model>> {
    let Some(id) = id else { return Ok(None) };
    let app = applications::Entity::find_by_id(id)
        .one(conn)
        .await
        .context("loading resource app")?
        .ok_or_else(|| OAuthError::invalid_grant("the resource no longer exists"))?;
    Ok(Some(app))
}

async fn authorization_code(
    state: &AppState,
    tenant: &Tenant,
    ip: Option<IpAddr>,
    client: &applications::Model,
    params: &HashMap<String, String>,
) -> OAuthResult<TokenSet> {
    let conn = &state.db;
    let code = required(params, "code")?;
    let redirect_uri = required(params, "redirect_uri")?;
    let verifier = required(params, "code_verifier")?;
    let row = tokens::code::find(conn, tenant.id, code)
        .await?
        .ok_or_else(|| OAuthError::invalid_grant("unknown authorization code"))?;
    if row.application_id != client.id {
        return Err(OAuthError::invalid_grant(
            "the code was issued to another client",
        ));
    }
    let now = chrono::Utc::now().fixed_offset();
    if row.consumed_at.is_some() {
        replay_detected(conn, &row, ip).await?;
        return Err(OAuthError::invalid_grant("authorization code already used"));
    }
    if tokens::code::is_expired(&row, now) {
        return Err(OAuthError::invalid_grant("authorization code expired"));
    }
    if row.redirect_uri != redirect_uri {
        return Err(OAuthError::invalid_grant(
            "redirect_uri does not match the authorization request",
        ));
    }
    // Before consuming: someone without the verifier can't burn the code.
    if !pkce::verify_s256(verifier, &row.code_challenge) {
        return Err(OAuthError::invalid_grant("PKCE verification failed"));
    }
    let user = active_user(conn, tenant.id, row.user_id).await?;
    let resource = load_app(conn, row.resource_application_id).await?;
    // The assignment may have gone since authorize.
    ensure_assigned(conn, tenant, &user, client, resource.as_ref()).await?;
    let (oidc, resource_scopes) = scope::split_stored(&row.scopes);
    let refresh = oidc.iter().any(|s| s == "offline_access").then(|| Refresh {
        family_id: Uuid::now_v7(),
        expires_at: now + Duration::seconds(i64::from(client.refresh_token_ttl_secs)),
        scopes: row.scopes.clone(),
        resource_app_id: row.resource_application_id,
    });
    // Consume and issue in ONE transaction: a concurrent redemption blocks
    // on the code's row lock until we commit, then finds it consumed and
    // revokes what we issued — no token of a replayed code survives.
    let txn = conn.begin().await?;
    // `user` was read before the lock: a disable that committed meanwhile
    // shows only here (it also ends the session `record_client` checks).
    if !backchannel::lock_user(&txn, tenant.id, row.user_id)
        .await?
        .is_active()
    {
        return Err(inactive_user());
    }
    // The code's session must still be live, and stays so (its row lock is
    // held to commit): a logout either already ended it — the code is dead
    // with it — or waits for us and then revokes and announces our tokens.
    if !backchannel::record_client(&txn, tenant.id, row.user_id, row.session_id, client.id).await? {
        return Err(OAuthError::invalid_grant("the sign-in session has ended"));
    }
    if !tokens::code::consume(&txn, row.id).await? {
        replay_detected(&txn, &row, ip).await?;
        txn.commit().await?;
        return Err(OAuthError::invalid_grant("authorization code already used"));
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
            nonce: row.nonce.as_deref(),
            oidc_scopes: &oidc,
            resource: resource.as_ref(),
            resource_scopes: &resource_scopes,
            authorization_code_id: Some(row.id),
            refresh,
        },
    )
    .await?;
    txn.commit().await?;
    Ok(set)
}

/// RFC 6749 §4.1.2: revoke what the code already produced.
async fn replay_detected(
    conn: &impl ConnectionTrait,
    code: &authorization_codes::Model,
    ip: Option<IpAddr>,
) -> OAuthResult<()> {
    tracing::warn!(code_id = %code.id, "authorization code replay; revoking tokens issued from it");
    tokens::refresh::revoke_by_code(conn, code.id).await?;
    let details = serde_json::json!({ "authorization_code_id": code.id });
    audit::token_replay(
        conn,
        audit::EventType::TokenCodeReplay,
        code.tenant_id,
        code.application_id,
        code.user_id,
        ip,
        details,
    )
    .await?;
    Ok(())
}

async fn client_credentials(
    state: &AppState,
    tenant: &Tenant,
    client: &applications::Model,
    params: &HashMap<String, String>,
) -> OAuthResult<TokenSet> {
    if client.client_type != ClientType::Confidential {
        return Err(OAuthError::new(
            ErrorCode::UnauthorizedClient,
            "client_credentials requires a confidential client",
        ));
    }
    let invalid_scope = || {
        OAuthError::new(
            ErrorCode::InvalidScope,
            "scope must be exactly `{resource}/.default`",
        )
    };
    let requested = scope::parse(required(params, "scope")?).map_err(|_| invalid_scope())?;
    let prefix = match (&requested.oidc[..], &requested.resource) {
        ([], Some((prefix, values)))
            if values.len() == 1 && values.iter().all(|v| v == scope::DEFAULT) =>
        {
            prefix
        }
        _ => return Err(invalid_scope()),
    };
    let resource = scope::find_resource(&state.db, tenant.id, prefix)
        .await?
        .ok_or_else(|| OAuthError::new(ErrorCode::InvalidScope, "unknown resource"))?;
    if !assignment::app_may_use(&state.db, client, &resource).await? {
        return Err(OAuthError::invalid_grant(assignment::NOT_ASSIGNED));
    }
    let issuer = state.config.issuer(&tenant.slug);
    let master_key = &state.config.master_key;
    Ok(tokens::issue_app_only(&state.db, master_key, tenant, &issuer, client, &resource).await?)
}
