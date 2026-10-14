// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Session reuse, prompt / max_age handling, admin consent and logout.
mod common;

use axum::http::StatusCode;
use common::{
    browser::{authorize_url, query_of},
    flow::{Fixture, WEB_CB},
};
use entity::consent_grants;
use sea_orm::{ActiveValue::Set, EntityTrait};
use uuid::Uuid;

#[tokio::test]
async fn prompt_none_login_and_max_age() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let url = |extra: &[(&str, &str)]| {
        authorize_url("web-app", WEB_CB, "openid api://orders/Orders.Read", extra)
    };

    // No session: prompt=none can't log in.
    let redirect = browser
        .authorize(&url(&[("prompt", "none")]))
        .await
        .unwrap_err();
    assert_eq!(query_of(&redirect)["error"], "login_required");

    // Sign in but decline consent: access_denied and no session.
    let tx = browser.authorize(&url(&[])).await.unwrap();
    let (_, resp) = browser
        .step(
            &tx,
            "password",
            serde_json::json!({ "email": "ann@example.com", "password": common::flow::PASSWORD }),
        )
        .await;
    assert_eq!(resp["step"], "consent");
    let (_, resp) = browser
        .step(&tx, "consent", serde_json::json!({ "approve": false }))
        .await;
    let q = query_of(resp["redirect"].as_str().unwrap());
    assert_eq!(q["error"], "access_denied");
    assert_eq!(q["state"], "st-1");
    // The session is created only when the flow completes.
    assert!(!browser.has_session());

    // Complete a login (with consent) to get a session.
    browser.login_for_code(&url(&[]), "ann@example.com").await;
    assert!(browser.has_session());
    // Session + consent: prompt=none succeeds silently.
    let redirect = browser
        .authorize(&url(&[("prompt", "none")]))
        .await
        .unwrap_err();
    assert!(query_of(&redirect).contains_key("code"), "{redirect}");
    // prompt=consent forces the consent screen even though it was granted.
    let tx = browser
        .authorize(&url(&[("prompt", "consent")]))
        .await
        .unwrap();
    let (_, _, body) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    assert!(body.contains(r#""step":"consent""#), "{body}");
    // prompt=login and max_age=0 force a fresh sign-in despite the session.
    for extra in [("prompt", "login"), ("max_age", "0")] {
        let tx = browser.authorize(&url(&[extra])).await.unwrap();
        let (_, _, body) = browser.get(&format!("/api/authn/tx/{tx}")).await;
        assert!(body.contains(r#""step":"password""#), "{extra:?}: {body}");
    }
    let redirect = browser
        .authorize(&url(&[("max_age", "3600")]))
        .await
        .unwrap_err();
    assert!(query_of(&redirect).contains_key("code"));

    // New scope without consent + prompt=none → consent_required.
    let other = authorize_url(
        "web-app",
        WEB_CB,
        "api://ledger/Ledger.Read",
        &[("prompt", "none")],
    );
    let redirect = browser.authorize(&other).await.unwrap_err();
    assert_eq!(query_of(&redirect)["error"], "consent_required");
}

#[tokio::test]
async fn admin_consent_required_blocks_until_granted() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let url = |extra: &[(&str, &str)]| {
        authorize_url(
            "web-app",
            WEB_CB,
            "openid api://orders/Orders.Manage",
            extra,
        )
    };

    // The user is never offered an admin-only scope.
    let tx = browser.authorize(&url(&[])).await.unwrap();
    let (_, resp) = browser
        .step(
            &tx,
            "password",
            serde_json::json!({ "email": "ann@example.com", "password": common::flow::PASSWORD }),
        )
        .await;
    let q = query_of(
        resp["redirect"]
            .as_str()
            .expect("redirect, not a consent step"),
    );
    assert_eq!(q["error"], "access_denied");
    assert!(
        q["error_description"].contains("admin approval required"),
        "{q:?}"
    );

    // Establish a session through a scope that needs no admin.
    browser
        .login_for_code(
            &authorize_url("web-app", WEB_CB, "openid", &[]),
            "ann@example.com",
        )
        .await;
    let redirect = browser
        .authorize(&url(&[("prompt", "none")]))
        .await
        .unwrap_err();
    assert_eq!(query_of(&redirect)["error"], "consent_required");
    let redirect = browser.authorize(&url(&[])).await.unwrap_err();
    assert_eq!(query_of(&redirect)["error"], "access_denied");

    // Tenant-wide admin grant: now it goes through without any prompt.
    consent_grants::Entity::insert(consent_grants::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(f.tenant.id),
        client_application_id: Set(f.web.id),
        resource_application_id: Set(f.orders.id),
        user_id: Set(None),
        scopes: Set(vec!["Orders.Manage".into()]),
        ..Default::default()
    })
    .exec_without_returning(&f.db)
    .await
    .unwrap();
    let redirect = browser.authorize(&url(&[])).await.unwrap_err();
    let code = query_of(&redirect)["code"].clone();
    let (status, tokens) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(status, StatusCode::OK);
    let at = f
        .verify_jwt(tokens["access_token"].as_str().unwrap(), "api://orders")
        .await;
    assert_eq!(at["scp"], "Orders.Manage");
}

#[tokio::test]
async fn builtin_spa_is_pre_consented() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let cb = format!("{}/admin/callback", common::ORIGIN);
    let url = authorize_url(
        "admin-portal",
        &cb,
        "openid api://management-api/Directory.AccessAsUser",
        &[],
    );
    let tx = browser.authorize(&url).await.unwrap();
    let redirect = browser.complete_login(&tx, "ann@example.com").await;
    assert!(redirect.starts_with(&format!("{cb}?code=")), "{redirect}");
}
