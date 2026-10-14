//! Email link redemption (`POST /api/authn/email/{verify,invite}`, and the
//! shared part of `…/reset`): the token in the body is the credential, so
//! these need no sign-in. A token only works on the host of the tenant that
//! issued it, once, before it expires; any failure is the same
//! `invalid_token`.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use entity::{
    email_tokens,
    enums::{EmailTokenPurpose, NotifyEvent, Outcome as AuditOutcome},
    users,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QuerySelect, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{AuthnError, AuthnResult, JsonBody, ctx::Ctx, ip::ClientIp, rate_limit};
use crate::{
    app::AppState,
    audit::{self, EventType},
    directory::{self, password},
    mail::tokens,
    notify,
    oidc::error::no_store,
    passkey,
    tenancy::Tenant,
};

/// Counts one attempt in every bucket; 429 when any is over its limit.
pub(super) async fn limit(
    ctx: &Ctx<'_>,
    buckets: &[(String, rate_limit::Limit)],
) -> AuthnResult<()> {
    let now = Utc::now();
    for (key, limit) in buckets {
        if let Err(retry_after) =
            rate_limit::hit(&ctx.state.db, ctx.tenant.id, key, *limit, now).await?
        {
            return Err(AuthnError::RateLimited { retry_after });
        }
    }
    Ok(())
}

pub(super) fn json(status: StatusCode, body: Value) -> Response {
    no_store((status, Json(body)).into_response())
}

pub(super) async fn record(
    conn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    event_type: EventType,
    user_id: uuid::Uuid,
    details: Value,
) -> anyhow::Result<()> {
    audit::record(
        conn,
        audit::Event {
            tenant_id: ctx.tenant.id,
            actor: audit::Actor::User(Some(user_id)),
            event_type,
            target: Some(audit::Target::User(user_id)),
            outcome: AuditOutcome::Success,
            ip: ctx.ip,
            details,
        },
    )
    .await
}

pub(super) async fn limit_links(ctx: &Ctx<'_>) -> AuthnResult<()> {
    let key = format!("link-{}", rate_limit::ip_key(ctx.ip));
    limit(ctx, &[(key, rate_limit::LINK_PER_IP)]).await
}

/// The user a consumed token may act on (`tokens::still_valid`), locked
/// for the rest of the transaction; anything else voids the attempt (the
/// caller's transaction rolls back, the token stays unused).
pub(super) async fn owner(
    conn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    token: &email_tokens::Model,
) -> AuthnResult<users::Model> {
    users::Entity::find_by_id(token.user_id)
        .filter(users::Column::TenantId.eq(ctx.tenant.id))
        .lock_exclusive()
        .one(conn)
        .await?
        .filter(|u| tokens::still_valid(token, u))
        .ok_or(AuthnError::InvalidLink)
}

#[derive(Deserialize)]
pub struct PasswordLinkBody {
    token: String,
    new_password: String,
}

/// Reset / invite completion: sets the password (signing the user out
/// everywhere, clearing `must_change_password`), marks the address
/// verified (the link proved the mailbox) and voids the user's other reset
/// and invite links (`directory::set_password`) — atomically with consuming
/// the token.
pub(super) async fn set_password_by_link(
    ctx: &Ctx<'_>,
    body: &PasswordLinkBody,
    purpose: EmailTokenPurpose,
) -> AuthnResult<()> {
    limit_links(ctx).await?;
    password::validate(&body.new_password)?;
    let tenant_id = ctx.tenant.id;
    let txn = ctx.state.db.begin().await?;
    let token = tokens::consume(&txn, tenant_id, &body.token, &[purpose])
        .await?
        .ok_or(AuthnError::InvalidLink)?;
    let user = owner(&txn, ctx, &token).await?;
    // A passkey accepted the invitation already: it is spent.
    if purpose == EmailTokenPurpose::Invite
        && passkey::store::count(&txn, tenant_id, user.id).await? > 0
    {
        return Err(AuthnError::InvalidLink);
    }
    directory::set_password(&txn, tenant_id, user.id, &body.new_password, false).await?;
    let mut row: users::ActiveModel = user.into();
    row.email_verified = Set(true);
    let user = row.update(&txn).await?;
    if purpose == EmailTokenPurpose::Invite {
        record(&txn, ctx, EventType::UserInviteAccept, user.id, Value::Null).await?;
    } else {
        record(
            &txn,
            ctx,
            EventType::PasswordResetComplete,
            user.id,
            Value::Null,
        )
        .await?;
        let facts = notify::change("reset with an email link");
        let config = &ctx.state.config;
        notify::event(
            &txn,
            config,
            ctx.tenant,
            &user,
            NotifyEvent::PasswordChanged,
            &facts,
        )
        .await?;
    }
    txn.commit().await?;
    Ok(())
}

pub async fn accept_invite(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    JsonBody(body): JsonBody<PasswordLinkBody>,
) -> AuthnResult<StatusCode> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    set_password_by_link(&ctx, &body, EmailTokenPurpose::Invite).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct VerifyBody {
    token: String,
}

/// Verifies the current address (`verify`) or applies a pending email
/// change (`change`: 409 if the new address was taken meanwhile; every
/// other link of the user dies with the old address, which is notified).
pub async fn verify(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    JsonBody(body): JsonBody<VerifyBody>,
) -> AuthnResult<Response> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    limit_links(&ctx).await?;
    let purposes = [EmailTokenPurpose::Verify, EmailTokenPurpose::Change];
    let txn = state.db.begin().await?;
    let token = tokens::consume(&txn, tenant.id, &body.token, &purposes)
        .await?
        .ok_or(AuthnError::InvalidLink)?;
    let user = owner(&txn, &ctx, &token).await?;
    let (old_email, old_verified) = (user.email.clone(), user.email_verified);
    let mut row: users::ActiveModel = user.into();
    row.email_verified = Set(true);
    let changing = token
        .new_email
        .filter(|_| token.purpose == EmailTokenPurpose::Change);
    if let Some(new_email) = &changing {
        row.email = Set(new_email.clone());
        row.updated_at = Set(Utc::now().fixed_offset());
    }
    let updated = row.update(&txn).await.map_err(|err| {
        if directory::violates_unique(&err, "users_tenant_email") {
            AuthnError::Conflict("that email address is already in use".into())
        } else {
            err.into()
        }
    })?;
    if changing.is_some() {
        tokens::invalidate(&txn, tenant.id, updated.id, &tokens::ALL).await?;
        let details = json!({ "email": updated.email });
        record(
            &txn,
            &ctx,
            EventType::EmailChangeComplete,
            updated.id,
            details,
        )
        .await?;
        let old = notify::OldAddress {
            email: &old_email,
            verified: old_verified,
        };
        notify::email_changed(&txn, &state.config, &tenant, &updated, old).await?;
    } else {
        let details = json!({ "email": updated.email });
        record(&txn, &ctx, EventType::EmailVerify, updated.id, details).await?;
    }
    txn.commit().await?;
    let purpose = if changing.is_some() {
        "change"
    } else {
        "verify"
    };
    Ok(json(
        StatusCode::OK,
        json!({ "purpose": purpose, "email": updated.email }),
    ))
}
