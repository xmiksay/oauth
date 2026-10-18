// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Telegram codes across link changes: MFA fails closed without a bot,
//! relinking / unlinking kill pending sign-in codes, link codes of disabled
//! accounts are spent.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    browser::{Browser, authorize_url},
    flow::{Fixture, PASSWORD, WEB_CB},
    mgmt::{call, mint_user_token, user_with_roles},
    seed::add_user,
    telegram::{CHAT, at_mfa, linked, sent_code},
};
use entity::{enums::DirectoryRole, telegram_otps};
use oauth_server::app::{self, AppState};
use sea_orm::{ConnectionTrait, EntityTrait, PaginatorTrait};
use serde_json::json;

async fn otps(f: &Fixture) -> u64 {
    telegram_otps::Entity::find().count(&f.db).await.unwrap()
}

#[tokio::test]
async fn a_linked_user_still_needs_a_second_factor_without_a_bot() {
    let f = linked().await;
    let mut config = f.config.clone();
    config.telegram = None;
    let state = AppState::new(f.db.clone(), config, true);
    let mut browser = Browser::new(app::router(state, common::no_web_dist()));
    let url = authorize_url("web-app", WEB_CB, "openid", &[]);
    let tx = browser.authorize(&url).await.unwrap();
    let password = json!({ "email": "ann@example.com", "password": PASSWORD });
    let (status, view) = browser.step(&tx, "password", password.clone()).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert!(
        view["redirect"].is_null(),
        "password alone signed in: {view}"
    );
    assert_eq!(view["step"], "mfa");
    // The factor is named (nothing else could be) but can't be used.
    assert_eq!(view["factors"], json!(["telegram"]));
    // Not 404: that would read as an expired sign-in; the tx is alive.
    for (step, body) in [
        ("telegram/send", json!({})),
        ("telegram", json!({ "code": "1" })),
    ] {
        let (status, err) = browser.step(&tx, step, body).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{step}: {err}");
        assert_eq!(err["error"], "telegram_unavailable");
    }
    let (status, _, _) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    assert_eq!(status, StatusCode::OK, "the transaction is still there");

    // With another factor, the unusable one isn't offered.
    f.enroll_totp(&f.user).await;
    let tx = browser.authorize(&url).await.unwrap();
    let (_, view) = browser.step(&tx, "password", password).await;
    assert_eq!(view["factors"], json!(["totp", "recovery"]));
}

#[tokio::test]
async fn relinking_kills_codes_sent_to_the_old_chat() {
    let f = linked().await;
    let (mut browser, tx, _) = at_mfa(&f).await;
    let code = sent_code(&f, &mut browser, &tx).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let other = f.link_code(&token).await;
    let reply = f
        .bot_says(CHAT + 1, "private", &format!("/start {other}"))
        .await;
    assert!(reply.unwrap().contains("now linked"));
    assert_eq!(otps(&f).await, 0);
    let (status, _) = browser.step(&tx, "telegram", json!({ "code": code })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn every_way_of_unlinking_kills_pending_codes() {
    let f = linked().await;
    let admin = user_with_roles(
        &f.db,
        f.tenant.id,
        "admin@example.com",
        &[DirectoryRole::GlobalAdmin],
    )
    .await;
    let admin = mint_user_token(&f.db, &f.config, &f.tenant, &admin).await;
    for how in ["reset-mfa", "/stop", "me"] {
        if how != "reset-mfa" {
            f.link_telegram(&f.user, CHAT).await;
            f.bot().take_messages();
        }
        let (mut browser, tx, _) = at_mfa(&f).await;
        sent_code(&f, &mut browser, &tx).await;
        assert_eq!(otps(&f).await, 1, "{how}");
        match how {
            "reset-mfa" => {
                let path = format!("/api/v1/users/{}/reset-mfa", f.user.id);
                let (s, _) = call(&f.app, Method::POST, &path, Some(&admin), None).await;
                assert_eq!(s, StatusCode::NO_CONTENT);
            }
            "/stop" => {
                f.bot_says(CHAT, "private", "/stop").await.unwrap();
            }
            _ => {
                let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
                let body = json!({ "password": PASSWORD });
                let path = "/api/v1/me/telegram";
                let (s, _) = call(&f.app, Method::DELETE, path, Some(&token), Some(&body)).await;
                assert_eq!(s, StatusCode::NO_CONTENT);
            }
        }
        assert_eq!(otps(&f).await, 0, "{how} left a live code");
    }
}

#[tokio::test]
async fn codes_of_disabled_users_and_tenants_are_spent() {
    let f = Fixture::with_telegram(false).await;
    let bob = add_user(&f.db, f.tenant.id, "bob@example.com", false).await;
    let ann_token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let bob_token = mint_user_token(&f.db, &f.config, &f.tenant, &bob).await;
    let ann_code = f.link_code(&ann_token).await;
    let bob_code = f.link_code(&bob_token).await;
    let db = &f.db;
    let sql = |q: String| async move { db.execute_unprepared(&q).await.unwrap() };
    let invalid = |reply: Option<String>| {
        assert!(reply.unwrap().contains("invalid or has expired"));
    };

    sql(format!(
        "UPDATE users SET disabled = true WHERE id = '{}'",
        f.user.id
    ))
    .await;
    invalid(
        f.bot_says(CHAT, "private", &format!("/start {ann_code}"))
            .await,
    );
    sql(format!(
        "UPDATE users SET disabled = false WHERE id = '{}'",
        f.user.id
    ))
    .await;
    invalid(
        f.bot_says(CHAT, "private", &format!("/start {ann_code}"))
            .await,
    );

    sql(format!(
        "UPDATE tenants SET disabled = true WHERE id = '{}'",
        f.tenant.id
    ))
    .await;
    invalid(
        f.bot_says(CHAT, "private", &format!("/start {bob_code}"))
            .await,
    );
    sql(format!(
        "UPDATE tenants SET disabled = false WHERE id = '{}'",
        f.tenant.id
    ))
    .await;
    invalid(
        f.bot_says(CHAT, "private", &format!("/start {bob_code}"))
            .await,
    );
    let links = entity::telegram_links::Entity::find()
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(links, 0);
}
