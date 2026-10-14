//! `GET|POST /oauth2/userinfo` (OIDC Core §5.3). Accepts access tokens
//! whose audience is this endpoint (i.e. requested with OIDC scopes only, as
//! Entra's userinfo requires a Graph token) and whose `scp` has `openid`.
//! The token is read from the `Authorization` header only.

use anyhow::Context;
use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use entity::users;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use super::{
    bearer,
    error::{ErrorCode, OAuthError, OAuthResult, no_store},
};
use crate::{
    app::AppState,
    tenancy::Tenant,
    tokens::{self, claims},
};

pub async fn userinfo(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
) -> Response {
    match handle(&state, &tenant, &headers).await {
        Ok(body) => no_store(Json(body).into_response()),
        Err(err) => err.into_response(),
    }
}

async fn handle(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
) -> OAuthResult<serde_json::Map<String, serde_json::Value>> {
    let token =
        bearer(headers).ok_or_else(|| OAuthError::invalid_token("bearer token required"))?;
    let issuer = state.config.issuer(&tenant.slug);
    let token_claims = tokens::inspect::access_token(&state.db, tenant.id, &issuer, token)
        .await?
        .ok_or_else(|| OAuthError::invalid_token("token is invalid or expired"))?
        .claims;
    if token_claims.get("aud").and_then(|a| a.as_str())
        != Some(tokens::userinfo_audience(&issuer).as_str())
    {
        return Err(OAuthError::invalid_token(
            "token audience is not the userinfo endpoint",
        ));
    }
    let scopes: Vec<String> = token_claims
        .get("scp")
        .and_then(|s| s.as_str())
        .unwrap_or_default()
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect();
    if !scopes.iter().any(|s| s == "openid") {
        return Err(OAuthError::new(
            ErrorCode::InsufficientScope,
            "the openid scope is required",
        ));
    }
    let user_id = tokens::inspect::user_of(&token_claims)
        .ok_or_else(|| OAuthError::invalid_token("token has no user"))?;
    let user = users::Entity::find_by_id(user_id)
        .filter(users::Column::TenantId.eq(tenant.id))
        .one(&state.db)
        .await
        .context("loading user")?
        .filter(|u| !u.disabled)
        .ok_or_else(|| OAuthError::invalid_token("the user is disabled or no longer exists"))?;
    Ok(claims::profile_claims(&user, &scopes))
}
