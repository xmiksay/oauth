// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Telegram: the webhook (secret, chat filter, `/start`, `/stop`), link
//! codes (expiry, reuse, replacement, tenants) and `me/telegram`.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    at,
    flow::{Fixture, PASSWORD},
    mgmt::{audited, call, mint_user_token},
    seed::add_user,
    telegram::{APEX, WEBHOOK_SECRET, message},
};
use oauth_server::directory::{self, NewTenant};
use sea_orm::ConnectionTrait;
use serde_json::{Value, json};

const CHAT: i64 = 5_550_001;

#[track_caller]
fn invalid(reply: Option<String>) {
    let reply = reply.unwrap();
    assert!(reply.contains("invalid or has expired"), "{reply}");
}

async fn status(f: &Fixture, token: &str) -> Value {
    let (code, body) = call(
        &f.app,
        Method::GET,
        "/api/v1/me/telegram",
        Some(token),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn the_webhook_needs_the_secret_and_wrong_ones_change_nothing() {
    let f = Fixture::with_telegram(false).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let code = f.link_code(&token).await;
    let update = message(CHAT, "private", &format!("/start {code}"));
    for secret in [None, Some("wrong"), Some(""), Some("hook-secret_012")] {
        let (s, body) = f.webhook_with(secret, &update).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{secret:?}: {body}");
    }
    assert_eq!(status(&f, &token).await["linked"], false);
    // The code survived the rejected calls.
    let (s, reply) = f.webhook_with(Some(WEBHOOK_SECRET), &update).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        reply["text"].as_str().unwrap().contains("Contoso"),
        "{reply}"
    );
    let linked = status(&f, &token).await;
    assert_eq!(linked["linked"], true);
    assert_eq!(linked["username"], "ann_tg");
    assert!(linked["linked_at"].is_string());
    // Only on the apex: a tenant host doesn't know the path.
    let req = axum::http::Request::post(at("contoso", "/telegram/webhook"))
        .header("x-telegram-bot-api-secret-token", WEBHOOK_SECRET)
        .body(axum::body::Body::from(update.to_string()))
        .unwrap();
    assert_eq!(
        common::browser::send(&f.app, req).await.0,
        StatusCode::NOT_FOUND
    );
    // Oversized bodies are refused before parsing.
    let big = json!({ "message": { "text": "x".repeat(70 * 1024) } });
    let (s, _) = f.webhook_with(Some(WEBHOOK_SECRET), &big).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn only_private_chats_count_and_other_input_gets_help() {
    let f = Fixture::with_telegram(false).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let code = f.link_code(&token).await;
    for kind in ["group", "supergroup", "channel"] {
        let reply = f.bot_says(CHAT, kind, &format!("/start {code}")).await;
        assert_eq!(reply, None, "{kind}");
        assert_eq!(f.bot_says(CHAT, kind, "/stop").await, None);
    }
    assert_eq!(status(&f, &token).await["linked"], false);
    let help = f.bot_says(CHAT, "private", "hi there").await.unwrap();
    assert!(help.contains("/stop"), "{help}");
    let (s, body) = f
        .webhook_with(Some(WEBHOOK_SECRET), &json!({ "update_id": 3 }))
        .await;
    assert_eq!((s, body), (StatusCode::OK, Value::Null));
    // The code still works in the private chat.
    let reply = f.bot_says(CHAT, "private", &format!("/start {code}")).await;
    assert!(reply.unwrap().contains("now linked"));
    let links = audited(&f.db, "user.mfa.telegram_link", f.user.id).await;
    assert_eq!(links, vec![json!({ "via": "bot" })]);
}

#[tokio::test]
async fn codes_are_single_use_expire_and_are_replaced() {
    let f = Fixture::with_telegram(false).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    invalid(f.bot_says(CHAT, "private", "/start").await);
    invalid(f.bot_says(CHAT, "private", "/start not-a-code").await);

    let code = f.link_code(&token).await;
    f.db.execute_unprepared("UPDATE telegram_link_codes SET expires_at = now() - interval '1 s'")
        .await
        .unwrap();
    invalid(f.bot_says(CHAT, "private", &format!("/start {code}")).await);

    let first = f.link_code(&token).await;
    let second = f.link_code(&token).await;
    invalid(
        f.bot_says(CHAT, "private", &format!("/start {first}"))
            .await,
    );
    assert!(
        f.bot_says(CHAT, "private", &format!("/start {second}"))
            .await
            .unwrap()
            .contains("now linked")
    );
    // Used once: another chat can't take it over.
    invalid(
        f.bot_says(CHAT + 1, "private", &format!("/start {second}"))
            .await,
    );
    let row =
        f.db.query_one_raw(sea_orm::Statement::from_string(
            f.db.get_database_backend(),
            "SELECT chat_id FROM telegram_links",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<i64>("", "chat_id").unwrap(), CHAT);

    // Linking again moves the user to the new chat.
    let again = f.link_code(&token).await;
    f.bot_says(CHAT + 2, "private", &format!("/start {again}"))
        .await
        .unwrap();
    let chats =
        f.db.query_all_raw(sea_orm::Statement::from_string(
            f.db.get_database_backend(),
            "SELECT chat_id FROM telegram_links",
        ))
        .await
        .unwrap();
    assert_eq!(chats.len(), 1);
    assert_eq!(chats[0].try_get::<i64>("", "chat_id").unwrap(), CHAT + 2);
}

#[tokio::test]
async fn codes_link_the_issuing_tenant_and_stop_unlinks_every_tenant() {
    let f = Fixture::with_telegram(false).await;
    let fabrikam = directory::create_tenant(
        &f.db,
        &f.config,
        NewTenant {
            slug: "fabrikam",
            display_name: "Fabrikam",
        },
    )
    .await
    .unwrap();
    let bob = add_user(&f.db, fabrikam.id, "bob@example.com", false).await;
    let ann_token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let bob_token = mint_user_token(&f.db, &f.config, &fabrikam, &bob).await;
    let bob_status = format!("{}/api/v1/me/telegram", at("fabrikam", ""));
    let (_, link) = call(
        &f.app,
        Method::POST,
        &format!("{bob_status}/link"),
        Some(&bob_token),
        Some(&json!({ "password": PASSWORD })),
    )
    .await;
    let bob_code = link["url"].as_str().unwrap().rsplit('=').next().unwrap();
    // A token of one tenant is useless on another's host.
    let (s, _) = call(&f.app, Method::GET, &bob_status, Some(&ann_token), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let reply = f
        .bot_says(CHAT, "private", &format!("/start {bob_code}"))
        .await
        .unwrap();
    assert!(
        reply.contains("Fabrikam") && reply.contains("b***@example.com"),
        "{reply}"
    );
    assert_eq!(status(&f, &ann_token).await["linked"], false);
    let (_, bob_view) = call(&f.app, Method::GET, &bob_status, Some(&bob_token), None).await;
    assert_eq!(bob_view["linked"], true);

    // The same chat links Ann in Contoso too; /stop ends both.
    f.link_telegram(&f.user, CHAT).await;
    let reply = f.bot_says(CHAT, "private", "/stop").await.unwrap();
    assert!(reply.contains("Unlinked 2 accounts"), "{reply}");
    assert_eq!(status(&f, &ann_token).await["linked"], false);
    let (_, bob_view) = call(&f.app, Method::GET, &bob_status, Some(&bob_token), None).await;
    assert_eq!(bob_view["linked"], false);
    for user in [f.user.id, bob.id] {
        let events = audited(&f.db, "user.mfa.telegram_unlink", user).await;
        assert_eq!(events, vec![json!({ "via": "bot" })]);
    }
    let reply = f.bot_says(CHAT, "private", "/stop").await.unwrap();
    assert!(reply.contains("No account"), "{reply}");
}

#[tokio::test]
async fn me_unlinks_after_reauthentication() {
    let f = Fixture::with_telegram(false).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let path = "/api/v1/me/telegram";
    let (app, token_ref) = (&f.app, &token);
    let unlink = |body: Value| async move {
        call(app, Method::DELETE, path, Some(token_ref), Some(&body)).await
    };
    assert_eq!(
        unlink(json!({ "password": PASSWORD })).await.0,
        StatusCode::NOT_FOUND
    );
    let (s, _) = call(
        &f.app,
        Method::POST,
        "/api/v1/me/telegram/link",
        Some(&token),
        Some(&json!({ "password": "wrong password!" })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    f.link_telegram(&f.user, CHAT).await;
    let (_, me) = call(&f.app, Method::GET, "/api/v1/me", Some(&token), None).await;
    assert_eq!(
        (&me["features"]["telegram"], &me["mfa"]["telegram"]),
        (&json!(true), &json!(true))
    );
    assert_eq!(
        unlink(json!({ "password": "wrong password!" })).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        unlink(json!({ "password": PASSWORD })).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(status(&f, &token).await["linked"], false);
    let events = audited(&f.db, "user.mfa.telegram_unlink", f.user.id).await;
    assert_eq!(events, vec![json!({ "via": "me" })]);
}

#[tokio::test]
async fn set_webhook_registers_the_apex_url_with_the_secret() {
    let f = Fixture::with_telegram(false).await;
    let url = oauth_server::telegram::set_webhook(&f.config)
        .await
        .unwrap();
    assert_eq!(url, format!("{APEX}/telegram/webhook"));
    let calls = f.bot().calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].bot, format!("bot{}", common::telegram::BOT_TOKEN));
    assert_eq!(calls[0].method, "setWebhook");
    assert_eq!(
        calls[0].body,
        json!({ "url": url, "secret_token": WEBHOOK_SECRET, "allowed_updates": ["message"] })
    );
    f.bot().fail_with(401);
    assert!(
        oauth_server::telegram::set_webhook(&f.config)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn without_a_bot_every_telegram_feature_is_hidden() {
    let f = Fixture::new().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let (s, _) = f
        .webhook_with(Some(WEBHOOK_SECRET), &message(CHAT, "private", "/stop"))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    for (method, path, body) in [
        (Method::GET, "/api/v1/me/telegram", None),
        (
            Method::POST,
            "/api/v1/me/telegram/link",
            Some(json!({ "password": PASSWORD })),
        ),
        (
            Method::DELETE,
            "/api/v1/me/telegram",
            Some(json!({ "password": PASSWORD })),
        ),
    ] {
        let (s, _) = call(&f.app, method, path, Some(&token), body.as_ref()).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
    }
    let (_, me) = call(&f.app, Method::GET, "/api/v1/me", Some(&token), None).await;
    assert_eq!(me["features"]["telegram"], false);
    let (_, prefs) = call(
        &f.app,
        Method::GET,
        "/api/v1/me/notifications",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(prefs["channels"]["telegram"], false);
    assert!(
        oauth_server::telegram::set_webhook(&f.config)
            .await
            .is_err()
    );
}
