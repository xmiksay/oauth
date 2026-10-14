//! Self-service password reset: `POST /api/authn/password-reset` mails a
//! 30-minute link; `POST /api/authn/email/reset` redeems it.
//!
//! No enumeration: the request answers `202` with the same body whether or
//! not the address belongs to anyone, and both rate-limit buckets are keyed
//! by IP and by the normalised address, never by a resolved account. A link
//! is sent only to an enabled user whose address is verified or who holds
//! a pending invitation (an unverified address may be someone else's).

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use std::net::IpAddr;

use anyhow::Context;
use entity::enums::{EmailTokenPurpose, Outcome};
use sea_orm::TransactionTrait;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    AuthnError, AuthnResult, JsonBody,
    ctx::Ctx,
    email::{PasswordLinkBody, json, limit, set_password_by_link},
    ip::ClientIp,
    rate_limit,
};
use crate::{
    app::AppState,
    audit::{self, EventType},
    directory,
    mail::{links, tokens},
    tenancy::Tenant,
};

#[derive(Deserialize)]
pub struct RequestBody {
    email: String,
}

pub async fn request(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    JsonBody(body): JsonBody<RequestBody>,
) -> AuthnResult<Response> {
    if !state.config.email_enabled() {
        return Err(AuthnError::EmailDisabled);
    }
    // Before any lookup or bucket, as at sign-in.
    if body.email.chars().any(char::is_control) || body.email.len() > 254 {
        return Err(AuthnError::Invalid("not a valid email address".into()));
    }
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let conn = &state.db;
    let lowered = rate_limit::lowered_email(conn, &body.email).await?;
    limit(
        &ctx,
        &[
            (
                format!("reset-{}", rate_limit::ip_key(ctx.ip)),
                rate_limit::RESET_PER_IP,
            ),
            (
                format!("reset-email:{lowered}"),
                rate_limit::RESET_PER_EMAIL,
            ),
        ],
    )
    .await?;
    // Everything that depends on whether the account exists happens after
    // the answer, so neither the status, the body nor the response time
    // tells known and unknown addresses apart.
    // Bounded: a flood of requests can't pile up unbounded work; past the
    // cap the request is dropped (it answers the same either way).
    match state.detached.clone().try_acquire_owned() {
        Ok(permit) => {
            let (tasks, state, tenant, ip) =
                (state.tasks.clone(), state.clone(), tenant.clone(), ctx.ip);
            tasks.spawn(async move {
                let _permit = permit;
                if let Err(err) = send_reset(&state, &tenant, ip, &body.email).await {
                    tracing::warn!(error = ?err, "queueing a password reset failed");
                }
            });
        }
        Err(_) => tracing::debug!("password reset dropped: too many in flight"),
    }
    Ok(json(StatusCode::ACCEPTED, json!({ "accepted": true })))
}

/// Queues the reset link if `email` names an enabled user whose address is
/// verified or who holds a pending invitation.
async fn send_reset(
    state: &AppState,
    tenant: &Tenant,
    ip: Option<IpAddr>,
    email: &str,
) -> anyhow::Result<()> {
    let txn = state
        .db
        .begin()
        .await
        .context("starting reset transaction")?;
    let Some(user) = directory::find_user_by_email(&txn, tenant.id, email)
        .await
        .context("looking up the reset account")?
        .filter(|u| !u.disabled)
    else {
        return Ok(());
    };
    let invited = tokens::invite_pending(&txn, tenant.id, user.id)
        .await
        .context("checking for a pending invitation")?;
    if !user.email_verified && !invited {
        return Ok(());
    }
    let purpose = EmailTokenPurpose::Reset;
    links::send(&txn, &state.config, tenant, &user, purpose, None)
        .await
        .context("queueing the reset link")?;
    // Anonymous: whoever asked is not known to be the user.
    audit::record(
        &txn,
        audit::Event {
            tenant_id: tenant.id,
            actor: audit::Actor::User(None),
            event_type: EventType::PasswordResetRequest,
            target: Some(audit::Target::User(user.id)),
            outcome: Outcome::Success,
            ip,
            details: Value::Null,
        },
    )
    .await
    .context("auditing the reset request")?;
    txn.commit().await.context("committing the reset request")?;
    Ok(())
}

/// Sets the new password; all sessions and refresh tokens end
/// (`directory::set_password`), MFA stays required.
pub async fn complete(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    JsonBody(body): JsonBody<PasswordLinkBody>,
) -> AuthnResult<StatusCode> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    set_password_by_link(&ctx, &body, EmailTokenPurpose::Reset).await?;
    Ok(StatusCode::NO_CONTENT)
}
