//! `me/telegram` — linking the user's Telegram chat. Linking issues a
//! single-use deep link after re-authentication; the link itself happens
//! when the user presses Start in the bot (`telegram::webhook`), which the
//! SPA observes by polling `GET me/telegram`. Unlinking re-authenticates
//! too: a linked chat is a sign-in factor.

use axum::{extract::State, http::StatusCode};
use serde_json::{Value, json};

use super::{Caller, extract::Json, me::me, me_mfa::mfa_notice, reauth::ReauthBody, ts};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    config::TelegramConfig,
    error::{AppError, AppResult},
    telegram::links,
};

fn require_telegram(state: &AppState) -> AppResult<&TelegramConfig> {
    state.config.telegram.as_ref().ok_or(AppError::NotFound)
}

pub async fn status(State(state): State<AppState>, caller: Caller) -> AppResult<axum::Json<Value>> {
    require_telegram(&state)?;
    let link = links::find(&state.db, caller.tenant_id(), caller.user_id()?).await?;
    Ok(axum::Json(json!({
        "linked": link.is_some(),
        "username": link.as_ref().and_then(|l| l.username.clone()),
        "linked_at": link.as_ref().map(|l| ts(&l.linked_at)),
    })))
}

/// A fresh deep link (10 minutes, single use; replaces an unused one).
pub async fn link(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<ReauthBody>,
) -> AppResult<axum::Json<Value>> {
    let telegram = require_telegram(&state)?;
    let user = me(&state, &caller).await?;
    body.verify(&state, &caller, &user).await?;
    let issued = links::issue_code(&state.db, user.tenant_id, user.id).await?;
    Ok(axum::Json(json!({
        "url": links::deep_link(&telegram.bot_username, &issued.code),
        "expires_at": ts(&issued.expires_at),
    })))
}

pub async fn unlink(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<ReauthBody>,
) -> AppResult<StatusCode> {
    require_telegram(&state)?;
    let user = me(&state, &caller).await?;
    if links::find(&state.db, user.tenant_id, user.id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound);
    }
    body.verify(&state, &caller, &user).await?;
    let txn = sea_orm::TransactionTrait::begin(&state.db).await?;
    if !links::unlink(&txn, user.tenant_id, user.id).await? {
        return Err(AppError::NotFound);
    }
    caller
        .audit(
            &txn,
            EventType::TelegramUnlink,
            Some(Target::User(user.id)),
            json!({ "via": "me" }),
        )
        .await?;
    mfa_notice(&state, &caller, &txn, &user, "Telegram unlinked").await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
