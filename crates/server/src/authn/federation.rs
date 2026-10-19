//! Signing in through an upstream identity provider:
//! `POST …/tx/{tx}/federation/{idp}` sends the browser upstream,
//! `GET /federation/callback` brings it back, `POST …/tx/{tx}/discover`
//! maps an email domain to its provider (home-realm discovery).
//!
//! The callback is a top-level GET from another site: it carries the
//! `SameSite=Lax` tx-binding cookie but no `Origin`, so the single-use
//! `state` bound to that cookie is what protects it. It always answers
//! with a redirect: to `/login?tx=…` (the SPA reloads the step, with
//! `&error=…` on refusal), to the client, or to My Account for a link.

use axum::{
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use entity::enums::{FederationPurpose, LoginStage, Outcome as AuditOutcome};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    AuthnError, AuthnResult, JsonBody, Outcome, ctx::Ctx, federation_link, federation_login,
    ip::ClientIp, rate_limit, tx,
};
use crate::{
    app::AppState,
    federation::{flow, idps, state},
    oidc::{error::no_store, params, redirect},
    tenancy::Tenant,
};

pub async fn start(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path((tx_id, idp_id)): Path<(String, String)>,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let tx = tx::load_at(&ctx, &tx_id, LoginStage::Password).await?;
    // Each start may cost a discovery fetch and creates a row.
    let key = format!("federation:{}", rate_limit::ip_key(ctx.ip));
    let limit = rate_limit::FEDERATION_PER_IP;
    if let Err(retry_after) = rate_limit::hit(&state.db, tenant.id, &key, limit, Utc::now()).await?
    {
        return Err(AuthnError::RateLimited { retry_after });
    }
    let idp_id = Uuid::parse_str(&idp_id).map_err(|_| AuthnError::NotFound)?;
    let idp = idps::find_enabled(&state.db, tenant.id, idp_id)
        .await?
        .ok_or(AuthnError::NotFound)?;
    let owner = state::Owner::Login { tx_id: tx.row.id };
    match flow::begin(
        &state,
        &tenant.slug,
        &idp,
        owner,
        &tx.row.binding_hash,
        flow::Reauth::of(&tx.req),
    )
    .await?
    {
        Ok(url) => Ok(Outcome::Redirect {
            url,
            cookies: Vec::new(),
        }),
        Err(failure) => {
            let details = flow::failure_details(failure.0, idp.id);
            ctx.audit_sign_in(&state.db, None, AuditOutcome::Failure, details)
                .await?;
            Err(AuthnError::Upstream)
        }
    }
}

#[derive(Deserialize)]
pub struct DiscoverBody {
    email: String,
}

/// Reveals only which provider a domain belongs to — the same for every
/// address of the domain, so nothing about accounts.
pub async fn discover(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
    JsonBody(body): JsonBody<DiscoverBody>,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    tx::load_at(&ctx, &tx_id, LoginStage::Password).await?;
    let key = format!("discover:{}", rate_limit::ip_key(ctx.ip));
    let limit = rate_limit::DISCOVER_PER_IP;
    if let Err(retry_after) = rate_limit::hit(&state.db, tenant.id, &key, limit, Utc::now()).await?
    {
        return Err(AuthnError::RateLimited { retry_after });
    }
    let found = match idps::email_domain(&body.email).filter(|_| body.email.len() <= 320) {
        Some(domain) => {
            let enabled = idps::enabled(&state.db, tenant.id).await?;
            idps::for_domain(&enabled, &domain).map(|idp| json!({ "id": idp.id, "name": idp.name }))
        }
        None => None,
    };
    Ok(Outcome::Step(match found {
        Some(idp) => json!({ "idp": idp }),
        None => json!({}),
    }))
}

/// A `302` the browser follows; never cached.
pub(super) fn go(url: &str) -> Response {
    no_store(redirect::found(url))
}

/// Where a callback lands when there is no live transaction to return to
/// (unknown, expired, replayed or foreign `state`).
pub(super) fn expired(ctx: &Ctx<'_>) -> Response {
    let origin = ctx.state.config.tenant_origin(&ctx.tenant.slug);
    go(&format!("{origin}/login?error=upstream_failed"))
}

pub async fn callback(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    match handle(&ctx, query.as_deref().unwrap_or("")).await {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(error = ?err, "federation callback failed");
            expired(&ctx)
        }
    }
}

async fn handle(ctx: &Ctx<'_>, query: &str) -> anyhow::Result<Response> {
    let Ok(params) = params::parse_unique(query.as_bytes()) else {
        return Ok(expired(ctx));
    };
    let Some(raw_state) = params.get("state") else {
        return Ok(expired(ctx));
    };
    // Consumed before anything else is checked: a state is good for one
    // callback, whatever that callback turns out to be.
    let consumed = state::consume(
        &ctx.state.db,
        &ctx.state.config.master_key,
        ctx.tenant.id,
        raw_state,
    )
    .await?;
    let Some(consumed) = consumed.filter(|c| tx::bound_to(ctx, &c.row.binding_hash)) else {
        return Ok(expired(ctx));
    };
    match consumed.row.purpose {
        FederationPurpose::Login => federation_login::complete(ctx, consumed, &params).await,
        FederationPurpose::Link => federation_link::complete(ctx, consumed, &params).await,
    }
}

/// A step result as a browser navigation: a step to render goes back to the
/// login page, a redirect is followed (setting its cookies).
pub(super) fn navigate(ctx: &Ctx<'_>, tx_id: Uuid, outcome: Outcome) -> Response {
    match outcome {
        Outcome::Step(_) => go(&login_url(ctx, tx_id, None)),
        Outcome::Redirect { url, cookies } => {
            let mut response = go(&url);
            for cookie in cookies {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, cookie);
            }
            response.into_response()
        }
    }
}

/// `/login?tx=…`, with `&error=code` (a fixed code) on refusal.
pub(super) fn login_url(ctx: &Ctx<'_>, tx_id: Uuid, error: Option<&str>) -> String {
    let origin = ctx.state.config.tenant_origin(&ctx.tenant.slug);
    match error {
        Some(code) => format!("{origin}/login?tx={tx_id}&error={code}"),
        None => format!("{origin}/login?tx={tx_id}"),
    }
}

/// Unused body placeholder for [`Outcome::Step`] when only a navigation follows.
pub(super) fn reload() -> Outcome {
    Outcome::Step(Value::Null)
}
