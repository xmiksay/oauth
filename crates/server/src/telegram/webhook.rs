//! `POST /telegram/webhook` on the apex host: the bot's incoming messages.
//!
//! Authenticated by the secret token Telegram echoes in
//! `X-Telegram-Bot-Api-Secret-Token` (constant-time compare; anything else
//! is 401 and never processed). Authenticated input always answers 200 —
//! ignored or not — so Telegram doesn't redeliver it. The bot's reply is
//! the response body itself (a `sendMessage` call Telegram performs), so
//! the webhook never waits on the Bot API.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use entity::{
    enums::{NotifyEvent, Outcome},
    tenants, users,
};
use sea_orm::{ConnectionTrait, EntityTrait, TransactionTrait};
use serde_json::json;
use uuid::Uuid;

use super::{
    api::send_message_body,
    links,
    update::{self, Command, Incoming},
};
use crate::{
    app::AppState,
    audit::{self, EventType, Target},
    error::AppError,
    notify, secret,
};

pub const PATH: &str = "/telegram/webhook";
/// Updates the bot asks for (text messages) are a few KiB at most.
pub const MAX_BODY: usize = 64 * 1024;
const SECRET_HEADER: &str = "x-telegram-bot-api-secret-token";

const INVALID_CODE: &str = "This link is invalid or has expired. To link this chat, use \
     \u{201c}Link Telegram\u{201d} in My Account.";
const HELP: &str = "This bot sends sign-in codes and security notices. Link it from My \
     Account; send /stop to unlink every account from this chat.";

pub fn router() -> Router<AppState> {
    Router::new()
        .route(PATH, post(receive))
        .layer(DefaultBodyLimit::max(MAX_BODY))
}

pub async fn receive(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(telegram) = state.config.telegram.as_ref() else {
        return AppError::NotFound.into_response();
    };
    let authentic = headers
        .get(SECRET_HEADER)
        .is_some_and(|v| secret::ct_eq(v.as_bytes(), telegram.webhook_secret.as_bytes()));
    if !authentic {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(incoming) = update::parse(&body, &telegram.bot_username) else {
        return StatusCode::OK.into_response();
    };
    match handle(&state, &incoming).await {
        Ok(text) => {
            let mut reply = send_message_body(incoming.chat_id, &text);
            if let Some(obj) = reply.as_object_mut() {
                obj.insert("method".into(), json!("sendMessage"));
            }
            Json(reply).into_response()
        }
        // 500: Telegram redelivers later, and nothing was committed.
        Err(err) => AppError::Internal(err).into_response(),
    }
}

/// Runs the command; the text to answer with.
async fn handle(state: &AppState, incoming: &Incoming) -> anyhow::Result<String> {
    match &incoming.command {
        Command::Start(Some(code)) => start(state, incoming, code).await,
        Command::Start(None) => Ok(INVALID_CODE.to_owned()),
        Command::Stop => stop(state, incoming.chat_id).await,
        Command::Other => Ok(HELP.to_owned()),
    }
}

/// The enabled tenant and user a link belongs to.
async fn account(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<Option<(tenants::Model, users::Model)>> {
    let tenant = tenants::Entity::find_by_id(tenant_id).one(conn).await?;
    let user = users::Entity::find_by_id(user_id).one(conn).await?;
    Ok(match (tenant, user) {
        (Some(t), Some(u)) if !t.disabled && !u.disabled && u.tenant_id == t.id => Some((t, u)),
        _ => None,
    })
}

/// Audits a link change; the user is told (`notify`) while their account
/// is enabled.
async fn record(
    conn: &impl ConnectionTrait,
    state: &AppState,
    (tenant_id, user_id): (Uuid, Uuid),
    event_type: EventType,
) -> anyhow::Result<()> {
    audit::record(
        conn,
        audit::Event {
            tenant_id,
            actor: audit::Actor::User(Some(user_id)),
            event_type,
            target: Some(Target::User(user_id)),
            outcome: Outcome::Success,
            ip: None,
            details: json!({ "via": "bot" }),
        },
    )
    .await?;
    let Some((tenant, user)) = account(conn, tenant_id, user_id).await? else {
        return Ok(());
    };
    let what = match event_type {
        EventType::TelegramLink => "Telegram linked",
        _ => "Telegram unlinked",
    };
    let facts = notify::change(what);
    notify::event(
        conn,
        &state.config,
        &tenant,
        &user,
        NotifyEvent::MfaChanged,
        &facts,
    )
    .await
}

async fn start(state: &AppState, incoming: &Incoming, code: &str) -> anyhow::Result<String> {
    let txn = state.db.begin().await?;
    let Some((tenant_id, user_id)) = links::consume_code(&txn, code).await? else {
        return Ok(INVALID_CODE.to_owned());
    };
    // A code of a since disabled user or tenant is spent all the same.
    let Some(owner) = account(&txn, tenant_id, user_id).await? else {
        txn.commit().await?;
        return Ok(INVALID_CODE.to_owned());
    };
    let username = incoming.username.as_deref();
    links::link(&txn, tenant_id, user_id, incoming.chat_id, username).await?;
    record(&txn, state, (tenant_id, user_id), EventType::TelegramLink).await?;
    txn.commit().await?;
    Ok(format!(
        "This chat is now linked to your {} account ({}). Sign-in codes and security notices \
         will arrive here; send /stop to unlink.",
        owner.0.display_name,
        crate::mail::templates::mask_email(&owner.1.email),
    ))
}

async fn stop(state: &AppState, chat_id: i64) -> anyhow::Result<String> {
    let txn = state.db.begin().await?;
    let mut unlinked = 0;
    for owner in links::links_of_chat(&txn, chat_id).await? {
        links::unlink(&txn, owner.0, owner.1).await?;
        record(&txn, state, owner, EventType::TelegramUnlink).await?;
        unlinked += 1;
    }
    txn.commit().await?;
    Ok(match unlinked {
        0 => "No account is linked to this chat.".to_owned(),
        1 => "Unlinked 1 account: no more codes or notices will arrive here.".to_owned(),
        n => format!("Unlinked {n} accounts: no more codes or notices will arrive here."),
    })
}
