//! Second factor: TOTP code, a one-time recovery code or a code sent via
//! Telegram. All count against the same rate limits as passwords.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
};
use entity::enums::{LoginStage, Outcome as AuditOutcome};
use serde::Deserialize;
use serde_json::json;

use super::{
    AuthnError, AuthnResult, JsonBody, Outcome, complete::proceed, ctx::Ctx, ip::ClientIp,
    password::limit, rate_limit, recovery, totp, tx,
};
use crate::{app::AppState, metrics, telegram::otp, tenancy::Tenant};

#[derive(Deserialize)]
pub struct CodeBody {
    code: String,
}

#[derive(Clone, Copy)]
enum Factor {
    Totp,
    Recovery,
    Telegram,
}

async fn second_factor(
    state: AppState,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    tx_id: String,
    code: String,
    factor: Factor,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let conn = &state.db;
    let mut tx = tx::load_at(&ctx, &tx_id, LoginStage::Mfa).await?;
    if matches!(factor, Factor::Telegram) && state.telegram.is_none() {
        return Err(AuthnError::TelegramUnavailable);
    }
    let user = tx::user_of(conn, &tx).await?;
    limit(&ctx, &rate_limit::user_key(user.id)).await?;
    let ok = match factor {
        Factor::Totp => match totp::confirmed(conn, tenant.id, user.id).await? {
            Some(row) => totp::verify_for_user(conn, &state.config.master_key, &row, &code).await?,
            None => false,
        },
        Factor::Recovery => recovery::redeem(conn, tenant.id, user.id, &code).await?,
        Factor::Telegram => otp::verify(conn, tenant.id, tx.row.id, user.id, &code).await?,
    };
    if !ok {
        metrics::login("mfa_failed");
        let factor = match factor {
            Factor::Totp => "totp",
            Factor::Recovery => "recovery_code",
            Factor::Telegram => "telegram",
        };
        let details = json!({ "reason": "mfa_failed", "factor": factor });
        ctx.audit_sign_in(conn, Some(user.id), AuditOutcome::Failure, details)
            .await?;
        return Err(AuthnError::InvalidCode);
    }
    // RFC 8176: first factor + one-time code = multi-factor. Recovery codes
    // and Telegram codes are one-time passwords too.
    tx.row.amr = tx::with_second_factor(&tx.row.amr, "otp");
    let next = user
        .must_change_password
        .then_some(LoginStage::ChangePassword);
    proceed(&ctx, tx, LoginStage::Mfa, next, &user, false).await
}

pub async fn totp(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
    JsonBody(body): JsonBody<CodeBody>,
) -> AuthnResult<Outcome> {
    second_factor(state, tenant, ip, headers, tx_id, body.code, Factor::Totp).await
}

pub async fn recovery(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
    JsonBody(body): JsonBody<CodeBody>,
) -> AuthnResult<Outcome> {
    second_factor(
        state,
        tenant,
        ip,
        headers,
        tx_id,
        body.code,
        Factor::Recovery,
    )
    .await
}

/// `POST …/tx/{tx}/telegram`: the code sent by `…/telegram/send`.
pub async fn telegram(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
    JsonBody(body): JsonBody<CodeBody>,
) -> AuthnResult<Outcome> {
    second_factor(
        state,
        tenant,
        ip,
        headers,
        tx_id,
        body.code,
        Factor::Telegram,
    )
    .await
}
