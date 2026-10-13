//! OIDC Discovery 1.0 metadata and the tenant's JWKS. Every advertised value
//! reflects what is actually implemented.

use axum::{
    Json,
    extract::State,
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::scope::OIDC_SCOPES;
use crate::{app::AppState, error::AppResult, keys, tenancy::Tenant};

pub async fn configuration(
    State(state): State<AppState>,
    tenant: Tenant,
) -> Json<serde_json::Value> {
    let issuer = state.config.issuer(&tenant.slug);
    let ep = |path: &str| format!("{issuer}/{path}");
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": ep("oauth2/authorize"),
        "token_endpoint": ep("oauth2/token"),
        "userinfo_endpoint": ep("oauth2/userinfo"),
        "jwks_uri": ep("discovery/keys"),
        "end_session_endpoint": ep("oauth2/logout"),
        "introspection_endpoint": ep("oauth2/introspect"),
        "revocation_endpoint": ep("oauth2/revoke"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": OIDC_SCOPES,
        "prompt_values_supported": ["none", "login", "consent"],
        "claims_supported": [
            "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "sid", "azp",
            "at_hash", "oid", "tid", "ver", "name", "preferred_username", "email",
            "email_verified",
        ],
        "claims_parameter_supported": false,
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "authorization_response_iss_parameter_supported": true,
        "frontchannel_logout_supported": false,
        "backchannel_logout_supported": false,
    }))
}

pub async fn jwks(State(state): State<AppState>, tenant: Tenant) -> AppResult<Response> {
    let body = keys::jwks(&state.db, tenant.id).await?;
    let mut response = Json(body).into_response();
    // Short enough that a pre-published key is picked up long before it
    // starts signing (KEY_PREPUBLISH_HOURS ≥ 1).
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    Ok(response)
}
