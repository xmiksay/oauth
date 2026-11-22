// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! A required MFA policy against the other kinds of factor: an upstream
//! sign-in (trusted for MFA or not) and a Telegram-only user.
mod common;

use axum::http::StatusCode;
use common::{
    federation::{Fed, code_of, is_login_page},
    flow::{Fixture, WEB_CB},
    mgmt::base32_decode,
    telegram::{at_mfa, linked, sent_code},
    upstream::Account,
};
use entity::{enums::MfaPolicy, tenants};
use oauth_server::authn::totp;
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use serde_json::{Map, Value, json};

async fn require_mfa(f: &Fixture) {
    let mut row: tenants::ActiveModel = f.tenant.clone().into();
    row.mfa_policy = Set(MfaPolicy::Required);
    row.update(&f.db).await.unwrap();
}

/// Redeems the code of a client redirect; returns the ID token's claims.
async fn id_claims(f: &Fixture, redirect: &str) -> Map<String, Value> {
    let code = code_of(redirect);
    let (status, tokens) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    f.verify_jwt(tokens["id_token"].as_str().unwrap(), "web-app")
        .await
}

fn code_for(secret_b32: &str) -> String {
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
    let secret = base32_decode(secret_b32);
    format!("{:06}", totp::hotp(&secret, now / totp::STEP_SECS))
}

#[tokio::test]
async fn an_untrusted_upstream_sign_in_enrols_a_factor_first() {
    let fed = Fed::new().await;
    require_mfa(&fed.f).await;
    let idp = fed.idp(json!({})).await;
    let mut account = Account::new("upstream-sub-1", "pat@upstream.example");
    account.amr = vec!["pwd".into(), "mfa".into()];
    fed.up.set_account(account);
    // Not trusted: the upstream's MFA doesn't count, and the JIT user has
    // no factor of ours.
    let mut browser = fed.f.browser();
    let (tx, location) = fed.sign_in(&mut browser, &idp).await;
    assert!(is_login_page(&location, &tx), "{location}");
    let (_, _, view) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    let view: Value = serde_json::from_str(&view).unwrap();
    assert_eq!(view["step"], "mfa_enroll", "{view}");
    let (status, pending) = browser.step(&tx, "enroll/totp", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    let code = code_for(pending["secret"].as_str().unwrap());
    let (status, body) = browser
        .step(&tx, "enroll/totp/confirm", json!({ "code": code }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, done) = browser.step(&tx, "enroll/continue", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{done}");
    let claims = id_claims(&fed.f, done["redirect"].as_str().unwrap()).await;
    assert_eq!(claims["amr"], json!(["fed", "otp", "mfa"]));
    assert_eq!(claims["acr"], "mfa");
}

#[tokio::test]
async fn trusted_upstream_mfa_satisfies_a_required_policy() {
    let fed = Fed::new().await;
    require_mfa(&fed.f).await;
    let idp = fed.idp(json!({})).await;
    fed.patch_idp(&idp, json!({ "trust_upstream_mfa": true }))
        .await;
    let mut account = Account::new("upstream-sub-1", "pat@upstream.example");
    account.amr = vec!["pwd".into(), "mfa".into()];
    fed.up.set_account(account);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    let claims = id_claims(&fed.f, &location).await;
    assert_eq!(claims["amr"], json!(["fed", "mfa"]));
    assert_eq!(claims["acr"], "mfa");
}

#[tokio::test]
async fn a_telegram_only_user_is_asked_for_their_telegram_code() {
    let f = linked().await;
    require_mfa(&f).await;
    let (mut browser, tx, view) = at_mfa(&f).await;
    assert_eq!(view["step"], "mfa", "{view}");
    assert_eq!(view["factors"], json!(["telegram"]));
    let code = sent_code(&f, &mut browser, &tx).await;
    let (status, done) = browser.step(&tx, "telegram", json!({ "code": code })).await;
    assert_eq!(status, StatusCode::OK, "{done}");
    let claims = id_claims(&f, done["redirect"].as_str().unwrap()).await;
    assert_eq!(claims["amr"], json!(["pwd", "otp", "mfa"]));
    assert_eq!(claims["acr"], "mfa");
}
