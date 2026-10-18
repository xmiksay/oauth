// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Telegram as a second factor at sign-in: sending codes (rate limit,
//! replacement, delivery failure) and checking them (attempt limit,
//! expiry, single use, amr).
mod common;

use axum::http::StatusCode;
use common::{
    browser::{authorize_url, query_of},
    flow::{Fixture, WEB_CB},
    telegram::{at_mfa, linked, send_code, sent_code},
};
use sea_orm::{ConnectionTrait, EntityTrait, PaginatorTrait};
use serde_json::json;

#[tokio::test]
async fn a_telegram_code_completes_the_sign_in_with_otp_amr() {
    let f = linked().await;
    let (mut browser, tx, view) = at_mfa(&f).await;
    // Linking Telegram makes it a second factor (no TOTP / passkey here).
    assert_eq!(view["step"], "mfa");
    assert_eq!(view["factors"], json!(["telegram"]));
    let code = sent_code(&f, &mut browser, &tx).await;
    let (status, done) = browser.step(&tx, "telegram", json!({ "code": code })).await;
    assert_eq!(status, StatusCode::OK, "{done}");
    let redirect = done["redirect"].as_str().unwrap();
    let auth_code = query_of(redirect).remove("code").unwrap();
    let (status, tokens) = f
        .redeem(&f.web, Some(&f.web_secret), &auth_code, WEB_CB)
        .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let claims = f
        .verify_jwt(tokens["id_token"].as_str().unwrap(), "web-app")
        .await;
    assert_eq!(claims["amr"], json!(["pwd", "otp", "mfa"]));
    // The finished transaction took its code with it.
    let left = entity::telegram_otps::Entity::find()
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn five_wrong_guesses_kill_the_code() {
    let f = linked().await;
    let (mut browser, tx, _) = at_mfa(&f).await;
    let code = sent_code(&f, &mut browser, &tx).await;
    let wrong = if code == "000000" { "111111" } else { "000000" };
    for _ in 0..5 {
        let (status, body) = browser
            .step(&tx, "telegram", json!({ "code": wrong }))
            .await;
        assert_eq!(
            (status, &body["error"]),
            (StatusCode::UNAUTHORIZED, &json!("invalid_code"))
        );
    }
    let (status, _) = browser.step(&tx, "telegram", json!({ "code": code })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "dead after five guesses");
    let failures = common::mgmt::audited(&f.db, "sign_in", f.user.id).await;
    assert!(
        failures
            .iter()
            .filter(|d| d["factor"] == "telegram")
            .count()
            >= 5
    );
    // A new code works again (spaces are fine).
    let code = sent_code(&f, &mut browser, &tx).await;
    let spaced = format!("{} {}", &code[..3], &code[3..]);
    let (status, done) = browser
        .step(&tx, "telegram", json!({ "code": spaced }))
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(done["redirect"].is_string());
}

#[tokio::test]
async fn codes_expire_and_a_new_send_replaces_the_old_code() {
    let f = linked().await;
    let (mut browser, tx, _) = at_mfa(&f).await;
    let code = sent_code(&f, &mut browser, &tx).await;
    f.db.execute_unprepared("UPDATE telegram_otps SET expires_at = now() - interval '1 s'")
        .await
        .unwrap();
    let (status, _) = browser.step(&tx, "telegram", json!({ "code": code })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "expired");

    let first = sent_code(&f, &mut browser, &tx).await;
    let second = sent_code(&f, &mut browser, &tx).await;
    if first != second {
        let (status, _) = browser
            .step(&tx, "telegram", json!({ "code": first }))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "replaced");
    }
    let (status, done) = browser
        .step(&tx, "telegram", json!({ "code": second }))
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
}

#[tokio::test]
async fn sends_are_limited_per_user_across_transactions() {
    let f = linked().await;
    let (mut browser, tx, _) = at_mfa(&f).await;
    for _ in 0..2 {
        sent_code(&f, &mut browser, &tx).await;
    }
    // A new transaction doesn't reset the user's budget.
    let (mut other, other_tx, _) = at_mfa(&f).await;
    sent_code(&f, &mut other, &other_tx).await;
    let (status, body) = send_code(&mut other, &other_tx).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    let (status, _) = send_code(&mut browser, &tx).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(f.bot().take_messages().is_empty());
}

#[tokio::test]
async fn delivery_failures_are_reported_and_retryable() {
    let f = linked().await;
    let (mut browser, tx, _) = at_mfa(&f).await;
    f.bot().fail_with(500);
    let (status, body) = send_code(&mut browser, &tx).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["error"], "delivery_failed");
    f.bot().fail_with(0);
    f.bot().take_messages();
    let code = sent_code(&f, &mut browser, &tx).await;
    let (status, _) = browser.step(&tx, "telegram", json!({ "code": code })).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn unlinked_users_have_no_telegram_factor() {
    let f = Fixture::with_telegram(false).await;
    f.enroll_totp(&f.user).await;
    let (mut browser, tx, view) = at_mfa(&f).await;
    assert_eq!(view["factors"], json!(["totp", "recovery"]));
    let (status, body) = send_code(&mut browser, &tx).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, _) = browser
        .step(&tx, "telegram", json!({ "code": "123456" }))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(f.bot().take_messages().is_empty());
    // Not at the MFA step yet: wrong step, nothing sent.
    let mut fresh = f.browser();
    let url = authorize_url("web-app", WEB_CB, "openid", &[]);
    let tx = fresh.authorize(&url).await.unwrap();
    assert_eq!(send_code(&mut fresh, &tx).await.0, StatusCode::CONFLICT);
    // CSRF: the login API wants the tenant's Origin.
    let (status, _, _) = fresh
        .post_json(
            &format!("/api/authn/tx/{tx}/telegram/send"),
            &json!({}),
            "https://evil.example",
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn without_a_bot_telegram_is_unavailable() {
    let f = Fixture::new().await;
    f.enroll_totp(&f.user).await;
    let (mut browser, tx, view) = at_mfa(&f).await;
    assert_eq!(view["factors"], json!(["totp", "recovery"]));
    let unavailable = (
        StatusCode::SERVICE_UNAVAILABLE,
        json!("telegram_unavailable"),
    );
    let (status, body) = send_code(&mut browser, &tx).await;
    assert_eq!((status, body["error"].clone()), unavailable);
    let (status, body) = browser
        .step(&tx, "telegram", json!({ "code": "123456" }))
        .await;
    assert_eq!((status, body["error"].clone()), unavailable);
    // Unknown transactions stay 404.
    let (status, _) = send_code(&mut browser, "00000000-0000-4000-8000-000000000000").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_code_works_once_even_while_the_transaction_lives() {
    use oauth_server::telegram::otp;
    let f = linked().await;
    let (_browser, tx, _) = at_mfa(&f).await;
    let tx: uuid::Uuid = tx.parse().unwrap();
    let (t, u) = (f.tenant.id, f.user.id);
    otp::store(&f.db, t, tx, u, "123456").await.unwrap();
    // Bound to its user and transaction.
    let stranger = uuid::Uuid::now_v7();
    assert!(!otp::verify(&f.db, t, tx, stranger, "123456").await.unwrap());
    assert!(otp::verify(&f.db, t, tx, u, "123456").await.unwrap());
    assert!(
        !otp::verify(&f.db, t, tx, u, "123456").await.unwrap(),
        "single use"
    );
}
