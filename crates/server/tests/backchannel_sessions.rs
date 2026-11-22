// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Every path that ends sessions queues their Back-Channel Logouts — and
//! only theirs: My Account (one / all), password change, disabling and
//! deleting a user, a new sign-in replacing the browser's session — and
//! recipients never cross tenants.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    backchannel::{queued, set_uri},
    browser::authorize_url,
    flow::{Fixture, PASSWORD, WEB_CB},
    mgmt::{call, mint_user_token, user_with_roles},
};
use entity::{enums::DirectoryRole, sessions, users};
use oauth_server::backchannel::{self, Ended};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::json;
use uuid::Uuid;

const RP: &str = "https://rp.example/bcl";

/// `f.user` signed in to `web-app` (which has a back-channel URI) in a
/// browser; returns that session's id.
async fn signed_in(f: &Fixture) -> (common::browser::Browser, Uuid) {
    set_uri(f, Some(RP)).await;
    let (browser, tokens) = f.web_tokens("openid", "ann@example.com").await;
    let claims = f
        .verify_jwt(tokens["id_token"].as_str().unwrap(), "web-app")
        .await;
    (browser, claims["sid"].as_str().unwrap().parse().unwrap())
}

async fn session_ids(f: &Fixture) -> Vec<Uuid> {
    sessions::Entity::find()
        .filter(sessions::Column::UserId.eq(f.user.id))
        .all(&f.db)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect()
}

async fn admin_token(f: &Fixture) -> String {
    let roles = [DirectoryRole::GlobalAdmin];
    let admin = user_with_roles(&f.db, f.tenant.id, "admin@example.com", &roles).await;
    mint_user_token(&f.db, &f.config, &f.tenant, &admin).await
}

#[tokio::test]
async fn me_revoke_session_is_scoped_to_the_caller() {
    let f = Fixture::new().await;
    let (_browser, sid) = signed_in(&f).await;
    let path = format!("/api/v1/me/sessions/{sid}");

    let bob = user_with_roles(&f.db, f.tenant.id, "bob@example.com", &[]).await;
    let bob_token = mint_user_token(&f.db, &f.config, &f.tenant, &bob).await;
    let (status, _) = call(&f.app, Method::DELETE, &path, Some(&bob_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(queued(&f).await.is_empty());
    assert!(session_ids(&f).await.contains(&sid));

    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let (status, body) = call(&f.app, Method::DELETE, &path, Some(&token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let rows = queued(&f).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].recipient, f.web.id.to_string());
    assert!(!session_ids(&f).await.contains(&sid));
}

#[tokio::test]
async fn me_revoke_all_notifies() {
    let f = Fixture::new().await;
    signed_in(&f).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let path = "/api/v1/me/sessions/revoke-all";
    let (status, body) = call(&f.app, Method::POST, path, Some(&token), Some(&json!({}))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(queued(&f).await.len(), 1);
}

#[tokio::test]
async fn password_change_notifies_the_other_sessions_only() {
    let f = Fixture::new().await;
    let (_browser, sid) = signed_in(&f).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    // The caller's own session also had `web-app` tokens: it is kept and
    // must not be notified.
    let current = session_ids(&f)
        .await
        .into_iter()
        .find(|id| *id != sid)
        .unwrap();
    backchannel::record_client(&f.db, f.tenant.id, f.user.id, current, f.web.id)
        .await
        .unwrap();

    let body = json!({ "current_password": PASSWORD, "new_password": "a brand new passphrase" });
    let path = "/api/v1/me/change-password";
    let (status, resp) = call(&f.app, Method::POST, path, Some(&token), Some(&body)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{resp}");
    assert_eq!(queued(&f).await.len(), 1);
    assert_eq!(session_ids(&f).await, vec![current]);
}

#[tokio::test]
async fn disabling_a_user_notifies() {
    let f = Fixture::new().await;
    signed_in(&f).await;
    let token = admin_token(&f).await;
    let path = format!("/api/v1/users/{}", f.user.id);
    let body = json!({ "disabled": true });
    let (status, resp) = call(&f.app, Method::PATCH, &path, Some(&token), Some(&body)).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(queued(&f).await.len(), 1);
}

#[tokio::test]
async fn deleting_a_user_notifies() {
    let f = Fixture::new().await;
    signed_in(&f).await;
    let token = admin_token(&f).await;
    let path = format!("/api/v1/users/{}", f.user.id);
    let (status, resp) = call(&f.app, Method::DELETE, &path, Some(&token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{resp}");
    let user = users::Entity::find_by_id(f.user.id)
        .one(&f.db)
        .await
        .unwrap();
    assert!(user.is_none());
    // The row outlives the user and is still deliverable.
    let rows = queued(&f).await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].body_enc.is_some());
}

#[tokio::test]
async fn a_new_sign_in_replacing_the_session_notifies() {
    let f = Fixture::new().await;
    let (mut browser, sid) = signed_in(&f).await;
    let url = authorize_url("web-app", WEB_CB, "openid", &[("prompt", "login")]);
    browser.login_for_code(&url, "ann@example.com").await;
    assert_eq!(queued(&f).await.len(), 1);
    assert!(!session_ids(&f).await.contains(&sid));
}

#[tokio::test]
async fn recipients_never_cross_tenants() {
    let f = Fixture::new().await;
    let (_browser, sid) = signed_in(&f).await;
    let key = &f.config.master_key;
    let other = Uuid::now_v7();
    // Another tenant id names neither the session nor the user.
    backchannel::record_client(&f.db, other, f.user.id, sid, f.web.id)
        .await
        .unwrap();
    backchannel::queue(&f.db, key, other, Ended::Session(sid))
        .await
        .unwrap();
    let ended = Ended::User {
        user_id: f.user.id,
        keep: None,
    };
    backchannel::queue(&f.db, key, other, ended).await.unwrap();
    assert!(queued(&f).await.is_empty());
    // The right tenant finds the one recorded client.
    backchannel::queue(&f.db, key, f.tenant.id, Ended::Session(sid))
        .await
        .unwrap();
    assert_eq!(queued(&f).await.len(), 1);
}
