// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! MFA policy at sign-in: forced enrolment (TOTP, passkey), step-up of a
//! single-factor session, `acr` in tokens.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    authenticator::{Alg, Authenticator, Tweak},
    browser::{Browser, authorize_url, current_totp, query_of},
    flow::{Fixture, PASSWORD, T, WEB_CB},
    mgmt::{audited, base32_decode, call, mint_user_token},
};
use entity::{
    applications,
    enums::{AppMfaPolicy, MfaPolicy},
    sessions, tenants,
};
use oauth_server::authn::totp;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
};
use serde_json::{Value, json};

const OPENID: &str = "openid";

async fn tenant_policy(f: &Fixture, policy: MfaPolicy) {
    let mut row: tenants::ActiveModel = f.tenant.clone().into();
    row.mfa_policy = Set(policy);
    row.update(&f.db).await.unwrap();
}

async fn app_policy(f: &Fixture, app: &applications::Model, policy: AppMfaPolicy) {
    let mut row: applications::ActiveModel = app.clone().into();
    row.mfa_policy = Set(policy);
    row.update(&f.db).await.unwrap();
}

fn url(scope: &str, extra: &[(&str, &str)]) -> String {
    authorize_url("web-app", WEB_CB, scope, extra)
}

/// Password step of a new transaction in `browser`: `(tx, response)`.
async fn password(browser: &mut Browser, scope: &str) -> (String, Value) {
    let tx = browser.authorize(&url(scope, &[])).await.unwrap();
    let body = json!({ "email": "ann@example.com", "password": PASSWORD });
    let (status, resp) = browser.step(&tx, "password", body).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    (tx, resp)
}

type Claims = serde_json::Map<String, Value>;

/// Redeems the code of `redirect`; returns the ID and access tokens' claims.
async fn token_claims(f: &Fixture, redirect: &str) -> (Claims, Claims) {
    let code = query_of(redirect)["code"].clone();
    let (status, tokens) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let id = f
        .verify_jwt(tokens["id_token"].as_str().unwrap(), "web-app")
        .await;
    let userinfo = format!("{}/oauth2/userinfo", common::ORIGIN);
    let access = f
        .verify_jwt(tokens["access_token"].as_str().unwrap(), &userinfo)
        .await;
    (id, access)
}

async fn id_claims(f: &Fixture, redirect: &str) -> Claims {
    token_claims(f, redirect).await.0
}

fn code_for(secret_b32: &str) -> String {
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
    let secret = base32_decode(secret_b32);
    format!("{:06}", totp::hotp(&secret, now / totp::STEP_SECS))
}

#[tokio::test]
async fn optional_policy_issues_no_acr_and_discovery_advertises_it() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let (_, resp) = password(&mut browser, OPENID).await;
    let claims = id_claims(&f, resp["redirect"].as_str().unwrap()).await;
    assert_eq!(claims["amr"], json!(["pwd"]));
    assert!(claims.get("acr").is_none());
    let (status, _, body) = browser.get("/.well-known/openid-configuration").await;
    assert_eq!(status, StatusCode::OK);
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["acr_values_supported"], json!(["mfa"]));
}

#[tokio::test]
async fn required_tenant_forces_totp_enrolment_before_the_code() {
    let f = Fixture::new().await;
    tenant_policy(&f, MfaPolicy::Required).await;
    let mut browser = f.browser();
    let (tx, resp) = password(&mut browser, OPENID).await;
    assert_eq!(resp["step"], "mfa_enroll", "{resp}");
    assert_eq!(resp["factors"], json!(["totp", "passkey"]));
    assert_eq!(resp["enrolled"], false);
    // Nothing else is accepted at this stage.
    let (status, _) = browser.step(&tx, "totp", json!({ "code": "123456" })).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = browser
        .step(&tx, "enroll/totp/confirm", json!({ "code": "123456" }))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "no pending enrolment yet");
    let (status, pending) = browser.step(&tx, "enroll/totp", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    let secret = pending["secret"].as_str().unwrap();
    let (status, body) = browser
        .step(&tx, "enroll/totp/confirm", json!({ "code": "000000x" }))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_code");
    let (status, done) = browser
        .step(
            &tx,
            "enroll/totp/confirm",
            json!({ "code": code_for(secret) }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["recovery_codes"].as_array().unwrap().len(), 10);
    // No code yet: it would expire while the user saves the recovery codes.
    assert_eq!(done.as_object().unwrap().len(), 1, "{done}");
    let (status, _, view) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    assert_eq!(status, StatusCode::OK);
    let view: Value = serde_json::from_str(&view).unwrap();
    assert_eq!(view["step"], "mfa_enroll", "{view}");
    assert_eq!(view["enrolled"], true, "{view}");
    let (status, _) = browser.step(&tx, "enroll/totp", json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT, "already enrolled");
    let (status, done) = browser.step(&tx, "enroll/continue", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (claims, access) = token_claims(&f, done["redirect"].as_str().unwrap()).await;
    assert_eq!(claims["amr"], json!(["pwd", "otp", "mfa"]));
    assert_eq!(claims["acr"], "mfa");
    assert_eq!(access["acr"], "mfa");
    let enrolled = audited(&f.db, "user.mfa.totp_enroll", f.user.id).await;
    assert_eq!(enrolled[0]["via"], "sign_in");
    // Next time the new factor is simply asked for.
    let (_, resp) = password(&mut f.browser(), OPENID).await;
    assert_eq!(resp["step"], "mfa", "{resp}");
}

#[tokio::test]
async fn required_tenant_accepts_a_new_passkey_as_the_second_factor() {
    let f = Fixture::new().await;
    tenant_policy(&f, MfaPolicy::Required).await;
    let mut browser = f.browser();
    let (tx, resp) = password(&mut browser, OPENID).await;
    assert_eq!(resp["step"], "mfa_enroll", "{resp}");
    let (status, options) = browser.step(&tx, "enroll/passkey/options", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{options}");
    let mut auth = Authenticator::new(Alg::Es256, T);
    let credential = auth.create(&options, &Tweak::default());
    let (status, done) = browser
        .step(&tx, "enroll/passkey", json!({ "credential": credential }))
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    let claims = id_claims(&f, done["redirect"].as_str().unwrap()).await;
    assert_eq!(claims["amr"], json!(["pwd", "hwk", "mfa"]));
    assert_eq!(claims["acr"], "mfa");
    let registered = audited(&f.db, "user.mfa.passkey_register", f.user.id).await;
    assert_eq!(registered[0]["via"], "sign_in");
}

#[tokio::test]
async fn enrolment_setup_calls_are_rate_limited() {
    let f = Fixture::new().await;
    tenant_policy(&f, MfaPolicy::Required).await;
    let mut browser = f.browser();
    let (tx, _) = password(&mut browser, OPENID).await;
    // Each call writes a row (and `enroll/totp` replaces the pending
    // secret): they share the account's attempt bucket.
    let mut answered = Vec::new();
    // One more than the account's 10 attempts per 15 min.
    for _ in 0..11 {
        let (status, _) = browser.step(&tx, "enroll/totp", json!({})).await;
        answered.push(status);
    }
    assert!(answered.contains(&StatusCode::OK), "{answered:?}");
    assert_eq!(answered.last(), Some(&StatusCode::TOO_MANY_REQUESTS));
    let (status, _) = browser.step(&tx, "enroll/passkey/options", json!({})).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn an_app_requiring_mfa_steps_up_a_single_factor_session() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let (_, resp) = password(&mut browser, OPENID).await;
    assert!(resp["redirect"].is_string(), "{resp}");
    let first_session = browser.cookies["__Host-oauth_sid"].clone();
    app_policy(&f, &f.web, AppMfaPolicy::Required).await;
    // prompt=none can't step up.
    let redirect = browser
        .authorize(&url(OPENID, &[("prompt", "none")]))
        .await
        .unwrap_err();
    assert_eq!(query_of(&redirect)["error"], "interaction_required");
    // Without a factor: the session alone can't add one (a stolen cookie
    // would register a passkey); the user signs in again, then enrols.
    let tx = browser.authorize(&url(OPENID, &[])).await.unwrap();
    let (status, _, view) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    assert_eq!(status, StatusCode::OK);
    let view: Value = serde_json::from_str(&view).unwrap();
    assert_eq!(view["step"], "password", "{view}");
    assert!(view["user"].is_null(), "{view}");
    for path in ["enroll/passkey/options", "enroll/totp"] {
        let (status, _) = browser.step(&tx, path, json!({})).await;
        assert_eq!(status, StatusCode::CONFLICT, "{path}");
    }
    let body = json!({ "email": "ann@example.com", "password": PASSWORD });
    let (_, resp) = browser.step(&tx, "password", body).await;
    assert_eq!(resp["step"], "mfa_enroll", "{resp}");
    // With one: the factor, then a new multi-factor session.
    f.enroll_totp(&f.user).await;
    let tx = browser.authorize(&url(OPENID, &[])).await.unwrap();
    let (status, resp) = browser
        .step(&tx, "totp", json!({ "code": current_totp() }))
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let claims = id_claims(&f, resp["redirect"].as_str().unwrap()).await;
    assert_eq!(claims["amr"], json!(["pwd", "otp", "mfa"]));
    assert_ne!(browser.cookies["__Host-oauth_sid"], first_session);
    // The stepped-up session is reused silently.
    let redirect = browser.authorize(&url(OPENID, &[])).await.unwrap_err();
    assert!(query_of(&redirect).contains_key("code"), "{redirect}");
}

#[tokio::test]
async fn a_resource_requiring_mfa_counts_too() {
    let f = Fixture::new().await;
    app_policy(&f, &f.orders, AppMfaPolicy::Required).await;
    let (_, resp) = password(&mut f.browser(), OPENID).await;
    assert!(
        resp["redirect"].is_string(),
        "only the resource requires it: {resp}"
    );
    let (_, resp) = password(&mut f.browser(), "openid api://orders/Orders.Read").await;
    assert_eq!(resp["step"], "mfa_enroll", "{resp}");
}

#[tokio::test]
async fn a_device_sign_in_steps_up_the_browser_session_too() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let (_, resp) = password(&mut browser, OPENID).await;
    assert!(resp["redirect"].is_string(), "{resp}");
    common::device::enable(&f, &f.spa).await;
    app_policy(&f, &f.spa, AppMfaPolicy::Required).await;
    f.enroll_totp(&f.user).await;
    let (status, started) = common::device::start(&f, &f.spa, None, OPENID).await;
    assert_eq!(status, StatusCode::OK, "{started}");
    let user_code = started["user_code"].as_str().unwrap();
    let tx = common::device::enter_tx(&mut browser, user_code).await;
    let (status, view) = browser
        .step(&tx, "totp", json!({ "code": current_totp() }))
        .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    // The device is still confirmed explicitly.
    assert_eq!(view["step"], "consent", "{view}");
}

#[tokio::test]
async fn a_step_up_fails_once_its_session_ended() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let (_, resp) = password(&mut browser, OPENID).await;
    assert!(resp["redirect"].is_string(), "{resp}");
    app_policy(&f, &f.web, AppMfaPolicy::Required).await;
    f.enroll_totp(&f.user).await;
    let tx = browser.authorize(&url(OPENID, &[])).await.unwrap();
    // Revoked (sign-out elsewhere, admin) while the factor is being entered.
    let revoke = sessions::Entity::delete_many().filter(sessions::Column::UserId.eq(f.user.id));
    revoke.exec(&f.db).await.unwrap();
    let (status, resp) = browser
        .step(&tx, "totp", json!({ "code": current_totp() }))
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let redirect = resp["redirect"].as_str().unwrap();
    assert_eq!(query_of(redirect)["error"], "login_required", "{redirect}");
    let left = sessions::Entity::find().filter(sessions::Column::UserId.eq(f.user.id));
    assert_eq!(left.count(&f.db).await.unwrap(), 0, "no session from it");
}

#[tokio::test]
async fn a_step_up_keeps_the_session_its_refresh_tokens_belong_to() {
    let f = Fixture::new().await;
    let (mut browser, tokens) = f
        .web_tokens("openid offline_access", "ann@example.com")
        .await;
    let old_refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    let mine = || sessions::Entity::find().filter(sessions::Column::UserId.eq(f.user.id));
    let single = mine().one(&f.db).await.unwrap().unwrap();
    // Signed in an hour ago, so a fresh `auth_time` is told apart.
    let hour_ago = chrono::Utc::now().fixed_offset() - chrono::Duration::hours(1);
    let mut row: sessions::ActiveModel = single.clone().into();
    row.auth_time = Set(hour_ago);
    row.update(&f.db).await.unwrap();
    app_policy(&f, &f.web, AppMfaPolicy::Required).await;
    f.enroll_totp(&f.user).await;
    let tx = browser.authorize(&url(OPENID, &[])).await.unwrap();
    let (status, resp) = browser
        .step(&tx, "totp", json!({ "code": current_totp() }))
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let claims = id_claims(&f, resp["redirect"].as_str().unwrap()).await;
    assert_eq!(claims["sid"], single.id.to_string());
    assert!(claims["auth_time"].as_i64().unwrap() > hour_ago.timestamp() + 60);
    let all = mine().all(&f.db).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, single.id);
    assert_eq!(all[0].amr, ["pwd", "otp", "mfa"]);
    // Signing the (stepped-up) session out ends its pre-step-up tokens too.
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let path = format!("/api/v1/me/sessions/{}", single.id);
    let (status, _) = call(&f.app, Method::DELETE, &path, Some(&token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = f.refresh(&old_refresh, None).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
}
