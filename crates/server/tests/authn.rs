// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Login JSON API: CSRF, rate limiting, credential errors, forced password
//! change and recovery codes.
mod common;

use axum::http::{StatusCode, header};
use common::{
    browser::authorize_url,
    flow::{Fixture, PASSWORD, T, WEB_CB},
    seed::add_user,
};
use entity::{user_recovery_codes, users};
use oauth_server::authn::recovery;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait};
use serde_json::json;
use uuid::Uuid;

fn openid() -> String {
    authorize_url("web-app", WEB_CB, "openid", &[])
}

#[tokio::test]
async fn csrf_requires_json_and_matching_origin() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let tx = browser.authorize(&openid()).await.unwrap();
    let path = format!("/{T}/api/authn/tx/{tx}/password");
    let body = json!({ "email": "ann@example.com", "password": PASSWORD });
    let (status, _, resp) = browser
        .post_json(&path, &body, "https://evil.example")
        .await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("csrf_rejected"))
    );

    let req = axum::http::Request::post(&path)
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::ORIGIN, common::PUBLIC_URL)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let (status, _, _) = browser.request(req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Still usable with a proper request.
    let (status, resp) = browser.step(&tx, "password", body).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(resp["redirect"].is_string());
    // A finished or unknown transaction is 404.
    let (status, _) = browser
        .step(&tx, "password", json!({ "email": "x", "password": "y" }))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = browser
        .step(
            &Uuid::nil().to_string(),
            "password",
            json!({ "email": "x", "password": "y" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn credential_errors_do_not_enumerate_and_disabled_is_refused() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let tx = browser.authorize(&openid()).await.unwrap();
    for (email, password) in [
        ("ann@example.com", "wrong password!"),
        ("nobody@example.com", PASSWORD),
    ] {
        let (status, resp) = browser
            .step(
                &tx,
                "password",
                json!({ "email": email, "password": password }),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(resp["error"], "invalid_credentials");
        assert_eq!(resp["error_description"], "invalid credentials");
    }
    // Wrong step for the transaction's state.
    let (status, resp) = browser.step(&tx, "totp", json!({ "code": "123456" })).await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::CONFLICT, Some("wrong_step"))
    );

    let mut disabled: users::ActiveModel = f.user.clone().into();
    disabled.disabled = Set(true);
    disabled.update(&f.db).await.unwrap();
    let (status, resp) = browser
        .step(
            &tx,
            "password",
            json!({ "email": "ann@example.com", "password": PASSWORD }),
        )
        .await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("account_disabled"))
    );
}

#[tokio::test]
async fn password_attempts_are_rate_limited() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let tx = browser.authorize(&openid()).await.unwrap();
    let wrong = json!({ "email": "Ann@Example.com", "password": "not the password" });
    for _ in 0..10 {
        let (status, _) = browser.step(&tx, "password", wrong.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let path = format!("/{T}/api/authn/tx/{tx}/password");
    let right = json!({ "email": "ann@example.com", "password": PASSWORD });
    let (status, headers, resp) = browser.post_json(&path, &right, common::PUBLIC_URL).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{resp}");
    assert_eq!(resp["error"], "rate_limited");
    let retry: u64 = headers[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=900).contains(&retry), "{retry}");
    // Other accounts are not locked by it.
    add_user(&f.db, f.tenant.id, "bob@example.com", false).await;
    let (status, _) = browser
        .step(
            &tx,
            "password",
            json!({ "email": "bob@example.com", "password": PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn recovery_code_and_forced_password_change() {
    let f = Fixture::new().await;
    let bob = add_user(&f.db, f.tenant.id, "bob@example.com", true).await;
    f.enroll_totp(&bob).await;
    user_recovery_codes::Entity::insert(user_recovery_codes::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(f.tenant.id),
        user_id: Set(bob.id),
        code_hash: Set(recovery::hash("abcd-efgh-1234")),
        used_at: Set(None),
        ..Default::default()
    })
    .exec_without_returning(&f.db)
    .await
    .unwrap();

    let mut browser = f.browser();
    let tx = browser.authorize(&openid()).await.unwrap();
    let (_, resp) = browser
        .step(
            &tx,
            "password",
            json!({ "email": "bob@example.com", "password": PASSWORD }),
        )
        .await;
    assert_eq!(resp["step"], "mfa");
    let (status, resp) = browser
        .step(&tx, "recovery", json!({ "code": "ABCD EFGH 1234" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["step"], "change_password");
    for (bad, why) in [(PASSWORD, "same as current"), ("short", "too short")] {
        let (status, _) = browser
            .step(&tx, "change-password", json!({ "new_password": bad }))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{why}");
    }
    let (status, resp) = browser
        .step(
            &tx,
            "change-password",
            json!({ "new_password": "a brand new passphrase" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(resp["redirect"].as_str().unwrap().starts_with(WEB_CB));
    let stored = users::Entity::find_by_id(bob.id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.must_change_password);

    // The recovery code was single use.
    let mut fresh = f.browser();
    let tx = fresh.authorize(&openid()).await.unwrap();
    let (_, resp) = fresh
        .step(
            &tx,
            "password",
            json!({ "email": "bob@example.com", "password": "a brand new passphrase" }),
        )
        .await;
    assert_eq!(resp["step"], "mfa");
    let (status, resp) = fresh
        .step(&tx, "recovery", json!({ "code": "abcd-efgh-1234" }))
        .await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_code"))
    );
}

#[tokio::test]
async fn control_character_emails_are_no_account_oracle() {
    let f = Fixture::new().await;
    add_user(&f.db, f.tenant.id, "known@example.com", false).await;
    let mut browser = f.browser();
    let tx = browser.authorize(&openid()).await.unwrap();
    let mut statuses = Vec::new();
    for email in ["known@example.com", "unknown@example.com"] {
        for _ in 0..10 {
            let body = json!({ "email": email, "password": "not the password" });
            let (status, _) = browser.step(&tx, "password", body).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        // Both accounts are now at their limit; a variant with a control
        // character must not reveal which one exists.
        let probe = json!({ "email": format!("{email}\u{7}"), "password": "x" });
        let (status, resp) = browser.step(&tx, "password", probe).await;
        assert_eq!(resp["error"], "invalid_request", "{email}: {resp}");
        statuses.push(status);
    }
    assert_eq!(statuses, [StatusCode::BAD_REQUEST, StatusCode::BAD_REQUEST]);
}
