// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Telegram notices: fan-out per preference, delivery by the outbox job
//! (chat looked up at send time), and the admin MFA reset unlinking.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{audited, call, mint_user_token, user_with_roles},
};
use entity::{
    enums::{Channel, DirectoryRole},
    outbox,
};
use oauth_server::{
    jobs::outbox::{Report, run_once},
    telegram::BotApi,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use serde_json::json;
use tokio_util::sync::CancellationToken;

const CHAT: i64 = 9_990_001;

/// One telegram outbox run now.
async fn deliver(f: &Fixture) -> Report {
    f.settle().await;
    let bot = BotApi::new(f.config.telegram.as_ref().unwrap()).unwrap();
    let now = chrono::Utc::now().fixed_offset();
    let clock = move || now;
    run_once(&f.db, &f.config, &bot, &clock, &CancellationToken::new())
        .await
        .unwrap()
        .unwrap()
}

async fn rows(f: &Fixture, channel: Channel) -> Vec<outbox::Model> {
    outbox::Entity::find()
        .filter(outbox::Column::Channel.eq(channel))
        .all(&f.db)
        .await
        .unwrap()
}

async fn clear_outbox(f: &Fixture) {
    f.db.execute_unprepared("DELETE FROM outbox").await.unwrap();
}

async fn admin_token(f: &Fixture) -> String {
    let admin = user_with_roles(
        &f.db,
        f.tenant.id,
        "admin@example.com",
        &[DirectoryRole::GlobalAdmin],
    )
    .await;
    mint_user_token(&f.db, &f.config, &f.tenant, &admin).await
}

async fn reset_password(f: &Fixture, admin: &str) {
    let (status, body) = call(
        &f.app,
        Method::POST,
        &format!("/api/v1/users/{}/reset-password", f.user.id),
        Some(admin),
        // The same password again: later steps re-authenticate with it.
        Some(&json!({ "password": common::flow::PASSWORD, "must_change_password": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn linking_is_announced_and_notices_reach_the_chat() {
    let f = Fixture::with_telegram(true).await;
    let user = f.verify(&f.user).await;
    f.link_telegram(&user, CHAT).await;
    // The "MFA changed" notice goes both ways.
    assert_eq!(rows(&f, Channel::Email).await.len(), 1);
    let queued = rows(&f, Channel::Telegram).await;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].recipient, user.id.to_string());
    assert_eq!(queued[0].kind, "notice_mfa_changed");
    f.bot().take_messages();
    assert_eq!(
        deliver(&f).await,
        Report {
            sent: 1,
            ..Report::default()
        }
    );
    let messages = f.bot().take_messages();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, CHAT);
    assert!(
        messages[0].1.contains("Telegram linked"),
        "{}",
        messages[0].1
    );
    assert!(
        messages[0]
            .1
            .starts_with("Your Contoso sign-in methods changed")
    );
    let sent = &rows(&f, Channel::Telegram).await[0];
    assert!(sent.sent_at.is_some() && sent.body_enc.is_none());
    // Email delivery is untouched by the Telegram run.
    assert!(rows(&f, Channel::Email).await[0].sent_at.is_none());
}

#[tokio::test]
async fn the_telegram_toggle_and_the_link_decide_the_fan_out() {
    let f = Fixture::with_telegram(true).await;
    let user = f.verify(&f.user).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &user).await;
    let admin = admin_token(&f).await;
    let prefs = "/api/v1/me/notifications";
    let (_, before) = call(&f.app, Method::GET, prefs, Some(&token), None).await;
    assert_eq!(
        before["channels"],
        json!({ "email": true, "telegram": false })
    );
    // Not linked: email only.
    reset_password(&f, &admin).await;
    assert_eq!(rows(&f, Channel::Telegram).await.len(), 0);

    f.link_telegram(&user, CHAT).await;
    // The reset ended the user's sessions, and with them the old token.
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &user).await;
    let (_, after) = call(&f.app, Method::GET, prefs, Some(&token), None).await;
    assert_eq!(
        after["channels"],
        json!({ "email": true, "telegram": true })
    );
    let off =
        json!({ "items": [{ "event": "password_changed", "email": true, "telegram": false }] });
    let (status, _) = call(&f.app, Method::PUT, prefs, Some(&token), Some(&off)).await;
    assert_eq!(status, StatusCode::OK);
    clear_outbox(&f).await;
    reset_password(&f, &admin).await;
    assert_eq!(rows(&f, Channel::Email).await.len(), 1);
    assert_eq!(rows(&f, Channel::Telegram).await.len(), 0);

    let on =
        json!({ "items": [{ "event": "password_changed", "email": false, "telegram": true }] });
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &user).await;
    let (status, _) = call(&f.app, Method::PUT, prefs, Some(&token), Some(&on)).await;
    assert_eq!(status, StatusCode::OK);
    clear_outbox(&f).await;
    reset_password(&f, &admin).await;
    assert_eq!(rows(&f, Channel::Email).await.len(), 0);
    assert_eq!(rows(&f, Channel::Telegram).await.len(), 1);
}

#[tokio::test]
async fn undeliverable_notices_die_and_outages_retry() {
    let f = Fixture::with_telegram(false).await;
    let admin = admin_token(&f).await;
    f.link_telegram(&f.user, CHAT).await;
    clear_outbox(&f).await;
    f.bot().take_messages();

    reset_password(&f, &admin).await;
    f.bot().fail_with(500);
    let report = deliver(&f).await;
    assert_eq!((report.retrying, report.dead), (1, 0));
    f.bot().fail_with(403);
    f.db.execute_unprepared("UPDATE outbox SET next_attempt_at = now() - interval '1 s'")
        .await
        .unwrap();
    assert_eq!(deliver(&f).await.dead, 1, "a blocked bot is permanent");
    f.bot().fail_with(0);
    f.bot().take_messages();

    // Unlinked after queueing: looked up at send time, dead, never retried.
    clear_outbox(&f).await;
    reset_password(&f, &admin).await;
    f.db.execute_unprepared("DELETE FROM telegram_links")
        .await
        .unwrap();
    assert_eq!(deliver(&f).await.dead, 1);
    assert!(f.bot().take_messages().is_empty());
    let dead = &rows(&f, Channel::Telegram).await[0];
    assert!(dead.dead_at.is_some() && dead.body_enc.is_none());
}

#[tokio::test]
async fn reset_mfa_unlinks_telegram() {
    let f = Fixture::with_telegram(false).await;
    let admin = admin_token(&f).await;
    f.link_telegram(&f.user, CHAT).await;
    let users = format!("/api/v1/users/{}", f.user.id);
    let (_, detail) = call(&f.app, Method::GET, &users, Some(&admin), None).await;
    assert_eq!(detail["mfa"]["telegram"], true);
    let (status, _) = call(
        &f.app,
        Method::POST,
        &format!("{users}/reset-mfa"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, detail) = call(&f.app, Method::GET, &users, Some(&admin), None).await;
    assert_eq!(detail["mfa"]["telegram"], false);
    let resets = audited(&f.db, "user.mfa_reset", f.user.id).await;
    assert_eq!(
        resets,
        vec![json!({ "passkeys_removed": 0, "telegram_unlinked": true })]
    );
    // Back to password-only sign-in.
    let reply = f.bot_says(CHAT, "private", "/stop").await.unwrap();
    assert!(reply.contains("No account"), "{reply}");
}

#[tokio::test]
async fn stop_tells_the_user_by_email() {
    let f = Fixture::with_telegram(true).await;
    let user = f.verify(&f.user).await;
    f.link_telegram(&user, CHAT).await;
    clear_outbox(&f).await;
    f.bot_says(CHAT, "private", "/stop").await.unwrap();
    let mails = rows(&f, Channel::Email).await;
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].kind, "notice_mfa_changed");
    assert_eq!(mails[0].recipient, user.email);
    // The chat is gone, so nothing is queued for it.
    assert!(rows(&f, Channel::Telegram).await.is_empty());
}
