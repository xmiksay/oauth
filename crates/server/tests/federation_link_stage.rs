//! Linking edge cases: stage `link` with a passkey and through consent, the
//! provider going away or changing policy while an identity is parked, an
//! account that already has an identity there, and My Account links bound
//! to their browser and session.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{
    ORIGIN,
    authenticator::{Alg, Tweak as KeyTweak},
    browser::Browser,
    federation::{Fed, IDPS, follow, is_login_page},
    flow::PASSWORD,
    mgmt::mint_user_token,
    passkeys::{enrolled, login_step},
    upstream::Account,
};
use entity::{federation_states, user_identities};
use sea_orm::{EntityTrait, PaginatorTrait};
use serde_json::{Value, json};

async fn linked(fed: &Fed) -> u64 {
    user_identities::Entity::find()
        .count(&fed.f.db)
        .await
        .unwrap()
}

async fn view(browser: &mut Browser, tx: &str) -> Value {
    let (_, _, body) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    serde_json::from_str(&body).unwrap()
}

/// A new transaction parked at stage `link` (policy `link_only`).
async fn parked(fed: &Fed, browser: &mut Browser, idp: &str, extra: &[(&str, &str)]) -> String {
    let tx = fed.authorize(browser, extra).await;
    let url = fed.begin(browser, &tx, idp).await;
    let location = fed.come_back(browser, &url).await;
    assert!(is_login_page(&location, &tx), "{location}");
    assert_eq!(view(browser, &tx).await["step"], "link");
    tx
}

fn ann() -> Value {
    json!({ "email": "ann@example.com", "password": PASSWORD })
}

#[tokio::test]
async fn a_passkey_or_a_consented_sign_in_links() {
    let fed = Fed::new().await;
    let mut key = enrolled(&fed.f, Alg::Es256).await;
    let idp = fed.idp(json!({ "policy": "link_only" })).await;
    let mut browser = fed.f.browser();
    let tx = parked(&fed, &mut browser, &idp, &[]).await;
    let (status, resp) = login_step(&mut browser, &tx, &mut key, &KeyTweak::default()).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(resp["redirect"].is_string(), "{resp}");
    assert_eq!(linked(&fed).await, 1);
    // A second provider, linked by a sign-in that still needs consent.
    let other = fed
        .idp(json!({ "policy": "link_only", "name": "Other" }))
        .await;
    fed.up
        .set_account(Account::new("second", "pat2@upstream.example"));
    let mut browser = fed.f.browser();
    let scope = [("scope", "openid api://orders/Orders.Read")];
    let tx = parked(&fed, &mut browser, &other, &scope).await;
    let (_, resp) = login_step(&mut browser, &tx, &mut key, &KeyTweak::default()).await;
    assert_eq!(resp["step"], "consent", "{resp}");
    assert_eq!(linked(&fed).await, 1, "not before the sign-in completes");
    let body = json!({ "approve": true, "scopes": ["Orders.Read"] });
    let (status, resp) = browser.step(&tx, "consent", body).await;
    assert!(resp["redirect"].is_string(), "{status} {resp}");
    assert_eq!(linked(&fed).await, 2);
}

#[tokio::test]
async fn a_provider_that_can_no_longer_link_releases_the_transaction() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({ "policy": "link_only" })).await;
    // Disabled while parked: the next view is the password step.
    let mut browser = fed.f.browser();
    let tx = parked(&fed, &mut browser, &idp, &[]).await;
    fed.patch_idp(&idp, json!({ "enabled": false })).await;
    let step = view(&mut browser, &tx).await;
    assert_eq!(
        (step["step"].as_str(), step["notice"].as_str()),
        (Some("password"), Some("link_unavailable"))
    );
    assert!(step["link"].is_null());
    fed.patch_idp(&idp, json!({ "enabled": true })).await;
    // Policy changed while parked: refused at the submission.
    let tx = parked(&fed, &mut browser, &idp, &[]).await;
    fed.patch_idp(&idp, json!({ "policy": "jit" })).await;
    let (status, resp) = browser.step(&tx, "password", ann()).await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::CONFLICT, Some("link_unavailable"))
    );
    assert_eq!(view(&mut browser, &tx).await["step"], "password");
    fed.patch_idp(&idp, json!({ "policy": "link_only" })).await;
    // Deleted while parked.
    let tx = parked(&fed, &mut browser, &idp, &[]).await;
    let (status, _) = fed
        .api(Method::DELETE, &format!("{IDPS}/{idp}"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(view(&mut browser, &tx).await["notice"], "link_unavailable");
    assert_eq!(linked(&fed).await, 0);
}

#[tokio::test]
async fn one_identity_per_provider_is_enforced_at_the_link_step() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({ "policy": "link_only" })).await;
    let mut browser = fed.f.browser();
    let tx = parked(&fed, &mut browser, &idp, &[]).await;
    browser.step(&tx, "password", ann()).await;
    assert_eq!(linked(&fed).await, 1);
    fed.up
        .set_account(Account::new("another-sub", "else@upstream.example"));
    let mut browser = fed.f.browser();
    let tx = parked(&fed, &mut browser, &idp, &[]).await;
    let (status, resp) = browser.step(&tx, "password", ann()).await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::CONFLICT, Some("already_linked"))
    );
    assert_eq!(linked(&fed).await, 1);
}

#[tokio::test]
async fn a_round_trip_completes_only_in_its_own_browser() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let mut victim = fed.f.browser();
    let tx = fed.authorize(&mut victim, &[]).await;
    let url = fed.begin(&mut victim, &tx, &idp).await;
    let callback = fed.up.authorize(&url);
    // Another browser with a valid binding cookie of its own.
    let mut other = fed.f.browser();
    fed.authorize(&mut other, &[]).await;
    assert!(other.cookies.contains_key("__Host-oauth_tx"));
    let expired = format!("{ORIGIN}/login?error=upstream_failed");
    assert_eq!(follow(&mut other, &callback).await, expired);
    assert_eq!(follow(&mut victim, &callback).await, expired, "burnt");
}

async fn bearer(
    browser: &mut Browser,
    token: &str,
    method: Method,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _, text) = browser.request(req).await;
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

#[tokio::test]
async fn my_account_links_need_reauth_and_a_live_session() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let token = mint_user_token(&fed.f.db, &fed.f.config, &fed.f.tenant, &fed.f.user).await;
    let mut browser = fed.f.browser();
    let link = format!("/api/v1/me/identities/{idp}/link");
    let (status, _) = bearer(
        &mut browser,
        &token,
        Method::POST,
        &link,
        json!({ "password": "no" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        federation_states::Entity::find()
            .count(&fed.f.db)
            .await
            .unwrap(),
        0
    );
    let reauth = json!({ "password": PASSWORD });
    let (status, body) = bearer(&mut browser, &token, Method::POST, &link, reauth).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Signed out everywhere before coming back.
    let revoke = "/api/v1/me/sessions/revoke-all";
    let (status, _) = bearer(&mut browser, &token, Method::POST, revoke, json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let location = fed
        .come_back(&mut browser, body["redirect"].as_str().unwrap())
        .await;
    assert_eq!(
        location,
        format!("{ORIGIN}/myaccount/security?federation_error=session_ended")
    );
    assert_eq!(linked(&fed).await, 0);
}
