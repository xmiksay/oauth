//! `POST /{t}/oauth2/revoke` (RFC 7009). A refresh token revokes its whole
//! family; an opaque access token is revoked; JWT access tokens can't be
//! recalled and simply expire. Unknown tokens and tokens of other clients
//! still get 200 (§2.2), so the endpoint is no token oracle.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use super::{
    client_auth,
    error::{OAuthError, OAuthResult, no_store},
    form_params,
};
use crate::{
    app::AppState,
    tenancy::Tenant,
    tokens::{opaque, refresh},
};

pub async fn revoke(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match handle(&state, &tenant, &headers, &body).await {
        Ok(()) => no_store(StatusCode::OK.into_response()),
        Err(err) => err.into_response(),
    }
}

async fn handle(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    body: &[u8],
) -> OAuthResult<()> {
    let conn = &state.db;
    let params = form_params(headers, body)?;
    let client = client_auth::authenticate(conn, tenant.id, headers, &params).await?;
    let token = params
        .get("token")
        .ok_or_else(|| OAuthError::invalid_request("token is required"))?;
    if let Some(row) = refresh::find(conn, tenant.id, token).await? {
        if row.application_id == client.id {
            refresh::revoke_family(conn, row.family_id).await?;
        }
        return Ok(());
    }
    if let Some(row) = opaque::find(conn, tenant.id, token).await?
        && row.application_id == client.id
    {
        opaque::revoke(conn, row.id).await?;
    }
    Ok(())
}
