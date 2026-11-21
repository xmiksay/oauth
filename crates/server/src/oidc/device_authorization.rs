//! `POST /oauth2/devicecode` — device authorization request (RFC 8628
//! §3.1–3.2). Only apps that opted in (`device_code_enabled`) may use it;
//! client authentication as at the token endpoint.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::{
    client_auth,
    error::{ErrorCode, OAuthError, OAuthResult, no_store},
    form_params, scope,
};
use crate::{
    app::AppState,
    authn::{AuthnError, ip::ClientIp, rate_limit},
    device_flow::{self, NewDevice},
    tenancy::Tenant,
};

/// Path of the SPA's verification page (`verification_uri`).
pub const VERIFICATION_PATH: &str = "/device";

pub async fn device_authorization(
    State(state): State<AppState>,
    tenant: Tenant,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Rows are created unauthenticated (public clients), so bound them per IP.
    let key = format!("devicecode:{}", rate_limit::ip_key(ip));
    let limit = rate_limit::DEVICE_AUTHORIZE_PER_IP;
    match rate_limit::hit(&state.db, tenant.id, &key, limit, chrono::Utc::now()).await {
        Ok(Ok(())) => {}
        Ok(Err(retry_after)) => return AuthnError::RateLimited { retry_after }.into_response(),
        Err(err) => return OAuthError::from(err).into_response(),
    }
    match handle(&state, &tenant, &headers, &body).await {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

async fn handle(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    body: &[u8],
) -> OAuthResult<Response> {
    let conn = &state.db;
    let params = form_params(headers, body)?;
    let client = client_auth::authenticate(conn, tenant.id, headers, &params).await?;
    if !client.device_code_enabled {
        return Err(OAuthError::new(
            ErrorCode::UnauthorizedClient,
            "the device code grant is not enabled for this client",
        ));
    }
    let raw = params.get("scope").map(String::as_str).unwrap_or_default();
    let scopes = scope::resolve_request(conn, &client, raw)
        .await?
        .map_err(|msg| OAuthError::new(ErrorCode::InvalidScope, msg))?;
    let mut stored = scopes.oidc;
    stored.extend(scopes.resource_scopes);
    let issued = device_flow::issue(
        conn,
        NewDevice {
            tenant_id: tenant.id,
            client_app_id: client.id,
            scopes: stored,
            resource_app_id: scopes.resource_id,
        },
    )
    .await?;
    let verification_uri = format!(
        "{}{VERIFICATION_PATH}",
        state.config.tenant_origin(&tenant.slug)
    );
    let complete = format!("{verification_uri}?user_code={}", issued.user_code);
    let body = json!({
        "device_code": issued.device_code,
        "user_code": issued.user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": complete,
        "expires_in": device_flow::TTL_SECS,
        "interval": device_flow::INTERVAL_SECS,
    });
    Ok(no_store(Json(body).into_response()))
}
