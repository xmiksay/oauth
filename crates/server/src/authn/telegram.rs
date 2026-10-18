//! Telegram as a second factor: `POST …/tx/{tx}/telegram/send` sends a
//! sign-in code to the user's linked chat (the code is checked by
//! `mfa::telegram`). The send is inline — a login is waiting for it — and a
//! failure is reported so the user can retry.

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use entity::enums::LoginStage;
use serde_json::json;
use uuid::Uuid;

use super::{AuthnError, AuthnResult, ctx::Ctx, ip::ClientIp, rate_limit, tx};
use crate::{
    app::AppState,
    metrics,
    oidc::error::no_store,
    telegram::{links, otp},
    tenancy::Tenant,
};

/// Whether the user has Telegram as a second factor: the link row alone.
/// Fails closed — a bot that is unset or unreachable never turns a linked
/// user's MFA off; they need another factor or an admin's Reset MFA.
pub async fn is_factor(state: &AppState, tenant_id: Uuid, user_id: Uuid) -> anyhow::Result<bool> {
    Ok(links::find(&state.db, tenant_id, user_id).await?.is_some())
}

pub async fn send(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
) -> AuthnResult<Response> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let conn = &state.db;
    let tx = tx::load_at(&ctx, &tx_id, LoginStage::Mfa).await?;
    let Some(bot) = state.telegram.as_ref() else {
        return Err(AuthnError::TelegramUnavailable);
    };
    let user = tx::user_of(conn, &tx).await?;
    let link = links::find(conn, tenant.id, user.id)
        .await?
        .ok_or_else(|| AuthnError::Invalid("no Telegram account is linked".into()))?;
    let key = format!("tg-otp:{}", user.id);
    if let Err(retry_after) =
        rate_limit::hit(conn, tenant.id, &key, otp::SEND_LIMIT, Utc::now()).await?
    {
        metrics::login("rate_limited");
        return Err(AuthnError::RateLimited { retry_after });
    }
    let code = otp::generate()?;
    // Stored before sending: a code that arrives always works.
    otp::store(conn, tenant.id, tx.row.id, user.id, &code).await?;
    bot.send_message(link.chat_id, &otp::message(&tenant.display_name, &code))
        .await
        .map_err(|_| AuthnError::DeliveryFailed)?;
    let body = json!({ "sent": true, "expires_in": otp::OTP_TTL_MINUTES * 60 });
    Ok(no_store(Json(body).into_response()))
}
