//! `POST /{t}/oauth2/introspect` (RFC 7662). Callers must be confidential
//! clients. A token is reported active only to the client it was issued to
//! or to the resource app it is for (by app id); anyone else gets
//! `{"active": false}`, indistinguishable from an invalid token.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use entity::{applications, enums::ClientType};
use serde_json::{Value, json};

use super::{
    client_auth,
    error::{ErrorCode, OAuthError, OAuthResult, no_store},
    form_params, scope,
    token::load_app,
};
use crate::{
    app::AppState,
    tenancy::Tenant,
    tokens::{
        inspect::{self, Inspected},
        refresh,
    },
};

pub async fn introspect(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match handle(&state, &tenant, &headers, &body).await {
        Ok(body) => no_store(Json(body).into_response()),
        Err(err) => err.into_response(),
    }
}

fn inactive() -> Value {
    json!({ "active": false })
}

async fn handle(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    body: &[u8],
) -> OAuthResult<Value> {
    let params = form_params(headers, body)?;
    let caller = client_auth::authenticate(&state.db, tenant.id, headers, &params).await?;
    if caller.client_type != ClientType::Confidential {
        return Err(OAuthError::new(
            ErrorCode::InvalidClient,
            "introspection requires a confidential client",
        ));
    }
    let token = params
        .get("token")
        .ok_or_else(|| OAuthError::invalid_request("token is required"))?;

    if let Some(row) = refresh::find(&state.db, tenant.id, token).await? {
        let now = chrono::Utc::now().fixed_offset();
        let usable = row.application_id == caller.id
            && refresh::state(&row, now) == refresh::State::Active
            && !refresh::family_revoked(&state.db, row.family_id).await?
            && inspect::user_active(&state.db, tenant.id, row.user_id).await?;
        if !usable {
            return Ok(inactive());
        }
        let resource = load_app(&state.db, row.resource_application_id).await?;
        let (oidc, values) = scope::split_stored(&row.scopes);
        let audience = resource.as_ref().map(scope::audience);
        return Ok(json!({
            "active": true,
            "token_type": "refresh_token",
            "client_id": caller.client_id,
            "sub": row.user_id,
            "scope": scope::granted_string(&oidc, audience.as_deref(), &values),
            "iat": row.created_at.timestamp(),
            "exp": row.expires_at.timestamp(),
        }));
    }

    let issuer = state.config.issuer(&tenant.slug);
    let Some(found) = inspect::access_token(&state.db, tenant.id, &issuer, token).await? else {
        return Ok(inactive());
    };
    if !may_introspect(&caller, &found) {
        return Ok(inactive());
    }
    let mut out = found.claims;
    let scope = out.get("scp").cloned();
    out.insert("active".into(), true.into());
    out.insert("token_type".into(), "Bearer".into());
    if let Some(scope) = scope {
        out.insert("scope".into(), scope);
    }
    Ok(Value::Object(out))
}

/// The token's client, or the resource app it is for (compared by id, not
/// by audience string).
fn may_introspect(caller: &applications::Model, found: &Inspected) -> bool {
    found.claims.get("client_id").and_then(Value::as_str) == Some(caller.client_id.as_str())
        || found.resource_app_id == Some(caller.id)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn app(client_id: &str) -> applications::Model {
        let now = chrono::Utc::now().fixed_offset();
        applications::Model {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            client_id: client_id.into(),
            display_name: "x".into(),
            client_type: ClientType::Confidential,
            builtin: false,
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
            identifier_uri: None,
            access_token_format: entity::enums::AccessTokenFormat::Opaque,
            signing_alg: entity::enums::SigningAlg::Rs256,
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 3600,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn only_client_or_resource_may_introspect() {
        let (web, orders, other) = (app("web"), app("orders"), app("other"));
        let claims = json!({ "client_id": "web", "aud": "api://other" });
        let found = Inspected {
            claims: claims.as_object().unwrap().clone(),
            resource_app_id: Some(orders.id),
        };
        assert!(may_introspect(&web, &found));
        assert!(may_introspect(&orders, &found));
        // Matching the audience string is not enough: identity is by app id.
        assert!(!may_introspect(&other, &found));
    }
}
