// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! An approved but not yet redeemed device request dies with the sign-in
//! that approved it: signing out of the approving browser, revoking that
//! session, "sign out everywhere", an admin password reset, or the session
//! expiring — the device's next poll gets `access_denied`, never tokens.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    ORIGIN,
    browser::Browser,
    device::{decide, enable, enter_tx, poll, rows, sign_in, start},
    flow::Fixture,
    mgmt::{call, mint_user_token, user_with_roles},
};
use entity::{
    enums::{DeviceStatus, DirectoryRole},
    refresh_tokens, sessions,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde_json::json;
use uuid::Uuid;

/// Ann approves a fresh `openid offline_access` request in a browser that
/// stays signed in; returns the browser, the device code and the approving
/// session's id.
async fn approved(f: &Fixture) -> (Browser, String, Uuid) {
    enable(f, &f.spa).await;
    let mut browser = f.browser();
    let (_, started) = start(f, &f.spa, None, "openid offline_access").await;
    let tx = enter_tx(&mut browser, started["user_code"].as_str().unwrap()).await;
    let view = sign_in(&mut browser, &tx, "ann@example.com").await;
    let url = decide(&mut browser, &tx, &view, true).await;
    assert_eq!(url, format!("{ORIGIN}/device?result=approved"));
    let row = rows(f).await.pop().unwrap();
    assert_eq!(row.status, DeviceStatus::Approved);
    let sid = row
        .approved_session_id
        .expect("approval records its session");
    let device_code = started["device_code"].as_str().unwrap().to_owned();
    (browser, device_code, sid)
}

/// The device polls: refused, and nothing was issued.
async fn refused(f: &Fixture, device_code: &str) {
    let sessions_before = sessions::Entity::find().count(&f.db).await.unwrap();
    let (status, body) = poll(f, &f.spa, None, device_code).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("access_denied")),
        "{body}"
    );
    let sessions_after = sessions::Entity::find().count(&f.db).await.unwrap();
    assert_eq!(sessions_after, sessions_before, "no device session");
    let issued = refresh_tokens::Entity::find().count(&f.db).await.unwrap();
    assert_eq!(issued, 0, "no refresh family");
}

#[tokio::test]
async fn signing_out_of_the_approving_browser_denies_the_device() {
    let f = Fixture::new().await;
    let (mut browser, device_code, sid) = approved(&f).await;
    let (status, _, body) = browser
        .post_json("/oauth2/logout", &json!({}), ORIGIN)
        .await;
    assert!(status.is_success() || status.is_redirection(), "{body}");
    let gone = sessions::Entity::find_by_id(sid).one(&f.db).await.unwrap();
    assert!(gone.is_none());
    assert_eq!(rows(&f).await[0].approved_session_id, None);
    refused(&f, &device_code).await;
}

#[tokio::test]
async fn revoking_the_approving_session_denies_the_device() {
    let f = Fixture::new().await;
    let (_browser, device_code, sid) = approved(&f).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let path = format!("/api/v1/me/sessions/{sid}");
    let (status, body) = call(&f.app, Method::DELETE, &path, Some(&token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    refused(&f, &device_code).await;
}

#[tokio::test]
async fn signing_out_everywhere_denies_the_device() {
    let f = Fixture::new().await;
    let (_browser, device_code, _) = approved(&f).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let path = "/api/v1/me/sessions/revoke-all";
    let (status, body) = call(&f.app, Method::POST, path, Some(&token), Some(&json!({}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let row = rows(&f).await.pop().unwrap();
    assert_eq!(row.status, DeviceStatus::Denied);
    assert_eq!(row.approved_session_id, None);
    refused(&f, &device_code).await;
}

#[tokio::test]
async fn an_admin_password_reset_denies_the_device() {
    let f = Fixture::new().await;
    let (_browser, device_code, _) = approved(&f).await;
    let roles = [DirectoryRole::GlobalAdmin];
    let admin = user_with_roles(&f.db, f.tenant.id, "admin@example.com", &roles).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &admin).await;
    let path = format!("/api/v1/users/{}/reset-password", f.user.id);
    let (status, body) = call(&f.app, Method::POST, &path, Some(&token), Some(&json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(rows(&f).await[0].status, DeviceStatus::Denied);
    refused(&f, &device_code).await;
}

#[tokio::test]
async fn an_expired_approving_session_denies_the_device() {
    let f = Fixture::new().await;
    let (_browser, device_code, sid) = approved(&f).await;
    f.db.execute_unprepared(&format!(
        "UPDATE sessions SET expires_at = now() - interval '1 second' WHERE id = '{sid}'"
    ))
    .await
    .unwrap();
    refused(&f, &device_code).await;
}

#[tokio::test]
async fn ending_another_session_keeps_the_approval() {
    let f = Fixture::new().await;
    let (_browser, device_code, sid) = approved(&f).await;
    // A second browser session of Ann's, signed out on its own.
    let (mut other, _) = f.web_tokens("openid", "ann@example.com").await;
    let (status, _, body) = other.post_json("/oauth2/logout", &json!({}), ORIGIN).await;
    assert!(status.is_success() || status.is_redirection(), "{body}");
    let left = sessions::Entity::find()
        .filter(sessions::Column::UserId.eq(f.user.id))
        .all(&f.db)
        .await
        .unwrap();
    assert_eq!(left.iter().map(|s| s.id).collect::<Vec<_>>(), [sid]);
    let (status, body) = poll(&f, &f.spa, None, &device_code).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["refresh_token"].is_string());
}
