// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The system admin's password reset: what its body may hold, and the
//! notice the user gets (`/api/v1/tenants/{slug}/users/{id}/reset-*`).
mod common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{
    browser::send,
    flow::{Fixture, T},
    mail::only_to,
    mgmt::{call, user_with_roles},
    tenant_users::{events, setup, setup_on, users_of},
};
use entity::enums::DirectoryRole::GlobalAdmin;
use serde_json::{Value, json};

#[tokio::test]
async fn reset_password_refuses_any_body_field_without_echoing_it() {
    let (f, _, _, token) = setup().await;
    let tok = Some(token.as_str());
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    // Only a generated password: any field is refused, nothing changes.
    let reset = users_of(T, &format!("/{}/reset-password", ga.id));
    for body in [
        json!({ "password": "an admin chosen passphrase" }),
        json!({ "must_change_password": false }),
    ] {
        let (st, _) = call(&f.app, Method::POST, &reset, tok, Some(&body)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    }
    // A bad body's error never quotes what was sent (it may be a password).
    // Nor a key: someone may send their intended password as one.
    for body in [json!("Hunter2!"), json!({ "Hunter2!": true })] {
        let (st, out) = call(&f.app, Method::POST, &reset, tok, Some(&body)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{out}");
        assert!(out["error"].is_string(), "{out}");
        assert!(!out.to_string().contains("Hunter2"), "{out}");
    }
    // Over axum's 2 MiB body limit: still a 413, in the JSON error shape.
    let req = Request::post(&reset)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(vec![b' '; 3 << 20]))
        .unwrap();
    let (st, _, out) = send(&f.app, req).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE, "{out}");
    let out: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(out["error"], "payload_too_large");
    // A field is refused even without a JSON Content-Type (not read as "no body").
    let req = Request::post(&reset)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(r#"{"password":"x"}"#))
        .unwrap();
    let (st, _, _) = send(&f.app, req).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(
        events(&f, f.tenant.id, "user.password_reset", ga.id)
            .await
            .is_empty()
    );
    // The body is optional: `{}` and a bare POST (no Content-Type) both reset.
    let (st, out) = call(&f.app, Method::POST, &reset, tok, Some(&json!({}))).await;
    assert_eq!(st, StatusCode::OK, "{out}");
    let (st, out) = call(&f.app, Method::POST, &reset, tok, None).await;
    assert_eq!(st, StatusCode::OK, "{out}");
    assert!(out["one_time_password"].is_string());
}

#[tokio::test]
async fn the_user_is_told_a_system_administrator_reset_them() {
    let (f, _, _, token) = setup_on(Fixture::with_email().await).await;
    let tok = Some(token.as_str());
    f.verify(&f.user).await;
    f.enroll_totp(&f.user).await;
    f.deliver().await; // anything enrollment queued
    let pw = users_of(T, &format!("/{}/reset-password", f.user.id));
    let (st, _) = call(&f.app, Method::POST, &pw, tok, None).await;
    assert_eq!(st, StatusCode::OK);
    let notice = f.deliver().await;
    let body = &only_to(&notice, &f.user.email).body;
    assert!(body.contains("reset by a system administrator"), "{body}");
    let mfa = users_of(T, &format!("/{}/reset-mfa", f.user.id));
    let (st, _) = call(&f.app, Method::POST, &mfa, tok, None).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let notice = f.deliver().await;
    let body = &only_to(&notice, &f.user.email).body;
    assert!(
        body.contains("second factors removed by a system administrator"),
        "{body}"
    );
}
