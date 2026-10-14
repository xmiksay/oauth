//! `me/verify-email`, `me/email` (self-service address change, applied when
//! the new address is verified) and `me/notifications`.

use axum::{extract::State, http::StatusCode};
use entity::enums::{EmailTokenPurpose, NotifyEvent};
use sea_orm::{ActiveEnum, TransactionTrait};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Caller, extract::Json, me::me, reauth, user_invite::require_email};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authn::rate_limit,
    directory::normalize_email,
    error::{AppError, AppResult},
    mail::links,
    notify::{self, Pref},
    passkey::AssertionJson,
};

/// Bounds the mail one account can make the server send.
async fn limit_mail(state: &AppState, caller: &Caller) -> AppResult<()> {
    let key = format!("mail-acct:{}", caller.user_id()?);
    let now = chrono::Utc::now();
    match rate_limit::hit(
        &state.db,
        caller.tenant_id(),
        &key,
        rate_limit::MAIL_PER_ACCOUNT,
        now,
    )
    .await?
    {
        Ok(()) => Ok(()),
        Err(retry_after) => Err(AppError::RateLimited { retry_after }),
    }
}

fn sent() -> (StatusCode, axum::Json<Value>) {
    (StatusCode::ACCEPTED, axum::Json(json!({ "sent": true })))
}

/// (Re)sends a verification link to the current address.
pub async fn send_verification(
    State(state): State<AppState>,
    caller: Caller,
) -> AppResult<(StatusCode, axum::Json<Value>)> {
    let user = me(&state, &caller).await?;
    require_email(&state)?;
    if user.email_verified {
        return Err(AppError::Conflict(
            "the email address is already verified".into(),
        ));
    }
    limit_mail(&state, &caller).await?;
    let txn = state.db.begin().await?;
    let purpose = EmailTokenPurpose::Verify;
    links::send(&txn, &state.config, &caller.tenant, &user, purpose, None).await?;
    caller
        .audit(
            &txn,
            EventType::EmailVerifyRequest,
            Some(Target::User(user.id)),
            Value::Null,
        )
        .await?;
    txn.commit().await?;
    Ok(sent())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeEmail {
    new_email: String,
    password: Option<String>,
    passkey: Option<AssertionJson>,
}

/// Mails a link to the NEW address; nothing changes until it is opened
/// (`POST /api/authn/email/verify`), which also notifies the old address.
/// Always 202 for a well-formed request with a valid re-authentication
/// (password or passkey).
pub async fn change_email(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<ChangeEmail>,
) -> AppResult<(StatusCode, axum::Json<Value>)> {
    let user = me(&state, &caller).await?;
    require_email(&state)?;
    let new_email = normalize_email(&body.new_email)?;
    reauth::verify(
        &state,
        &caller,
        &user,
        body.password.as_deref(),
        body.passkey.as_ref(),
    )
    .await?;
    limit_mail(&state, &caller).await?;
    if new_email.to_lowercase() == user.email.to_lowercase() {
        return Err(AppError::BadRequest(
            "the new address is the current one".into(),
        ));
    }
    // No "taken" check here: a 409 would let a signed-in user probe which
    // addresses have accounts. Applying the link enforces uniqueness (409).
    let txn = state.db.begin().await?;
    let purpose = EmailTokenPurpose::Change;
    links::send(
        &txn,
        &state.config,
        &caller.tenant,
        &user,
        purpose,
        Some(&new_email),
    )
    .await?;
    caller
        .audit(
            &txn,
            EventType::EmailChangeRequest,
            Some(Target::User(user.id)),
            json!({ "new_email": new_email }),
        )
        .await?;
    txn.commit().await?;
    Ok(sent())
}

fn prefs_view(state: &AppState, prefs: &[Pref]) -> Value {
    let items: Vec<Value> = prefs
        .iter()
        .map(|p| json!({ "event": p.event.to_value(), "email": p.email, "telegram": p.telegram }))
        .collect();
    json!({
        "channels": { "email": state.config.email_enabled(), "telegram": false },
        "items": items,
    })
}

pub async fn notifications(
    State(state): State<AppState>,
    caller: Caller,
) -> AppResult<axum::Json<Value>> {
    let prefs = notify::prefs(&state.db, caller.tenant_id(), caller.user_id()?).await?;
    Ok(axum::Json(prefs_view(&state, &prefs)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefItem {
    event: String,
    email: bool,
    telegram: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePrefs {
    items: Vec<PrefItem>,
}

pub async fn update_notifications(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<UpdatePrefs>,
) -> AppResult<axum::Json<Value>> {
    let user_id = caller.user_id()?;
    let tenant_id = caller.tenant_id();
    let current = notify::prefs(&state.db, tenant_id, user_id).await?;
    let mut changed: Vec<Pref> = Vec::new();
    let mut seen: Vec<NotifyEvent> = Vec::new();
    for item in &body.items {
        let event = NotifyEvent::try_from_value(&item.event)
            .map_err(|_| AppError::BadRequest(format!("unknown event `{}`", item.event)))?;
        if seen.contains(&event) {
            return Err(AppError::BadRequest(format!(
                "event `{}` listed twice",
                item.event
            )));
        }
        seen.push(event);
        let old = current.iter().find(|p| p.event == event);
        let pref = Pref {
            event,
            email: item.email,
            telegram: item.telegram.or(old.map(|p| p.telegram)).unwrap_or(true),
        };
        if old != Some(&pref) {
            changed.push(pref);
        }
    }
    if changed.is_empty() {
        return Ok(axum::Json(prefs_view(&state, &current)));
    }
    let txn = state.db.begin().await?;
    notify::set_prefs(&txn, tenant_id, user_id, &changed).await?;
    let events: Vec<String> = changed.iter().map(|p| p.event.to_value()).collect();
    caller
        .audit(
            &txn,
            EventType::NotificationPrefsUpdate,
            Some(Target::User(user_id)),
            json!({ "events": events }),
        )
        .await?;
    let prefs = notify::prefs(&txn, tenant_id, user_id).await?;
    txn.commit().await?;
    Ok(axum::Json(prefs_view(&state, &prefs)))
}
