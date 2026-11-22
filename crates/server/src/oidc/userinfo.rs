//! `GET|POST /oauth2/userinfo` (OIDC Core §5.3). Accepts access tokens
//! whose audience is this endpoint (i.e. requested with OIDC scopes only, as
//! Entra's userinfo requires a Graph token) and whose `scp` has `openid`.
//! The token is read from the `Authorization` header only. `groups` follow
//! the token's client app (`id_token_groups`), read at call time.

use anyhow::Context;
use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use entity::{applications, users};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use super::{
    bearer,
    error::{ErrorCode, OAuthError, OAuthResult, no_store},
};
use crate::{
    app::AppState,
    tenancy::Tenant,
    tokens::{self, claims, principal},
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
    let mut body = claims::profile_claims(&user, &scopes);
    let client_id = token_claims.get("client_id").and_then(|c| c.as_str());
    let client = applications::Entity::find()
        .filter(applications::Column::TenantId.eq(tenant.id))
        .filter(applications::Column::ClientId.eq(client_id.unwrap_or_default()))
        .one(&state.db)
        .await
        .context("loading client app")?;
    // A client deleted since issuance lists no groups.
    if let Some(client) = client {
        let groups = principal::user_groups(&state.db, tenant.id, user.id).await?;
        let values =
            principal::id_token_group_values(&state.db, tenant.id, &client, &groups).await?;
        claims::insert_groups(&mut body, &values);
    }
    Ok(body)
}
