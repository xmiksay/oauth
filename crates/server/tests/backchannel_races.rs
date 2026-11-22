// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Lock order user → session → tokens: a logout or an admin revocation
//! racing a refresh / code redemption of the same session never deadlocks,
//! and the grant that loses is a plain `invalid_grant`, not a replay alarm.
mod common;

use axum::http::StatusCode;
use common::{
    backchannel::{logout_url, wait_for_lock_waiter},
    browser::authorize_url,
    device::{approve_as, enable, poll, start},
    flow::{Fixture, PASSWORD, WEB_CB},
};
use entity::{audit_events, sessions, users};
use oauth_server::{
    backchannel::{self, Ended},
    directory,
    tokens::refresh,
};
use sea_orm::{
    ColumnTrait, DatabaseTransaction, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect,
    TransactionTrait,
};
use uuid::Uuid;

const SCOPE: &str = "openid offline_access";

async fn replay_alarms(f: &Fixture) -> u64 {
    audit_events::Entity::find()
        .filter(audit_events::Column::EventType.eq("token.refresh_reuse"))
        .count(&f.db)
        .await
        .unwrap()
}

/// Deterministic interleaving: the logout holds the session lock, the
/// refresh starts, then the logout revokes the session's tokens. With the
/// refresh taking the token row first this deadlocks.
#[tokio::test]
async fn refresh_waits_for_a_logout_holding_the_session() {
    let f = Fixture::new().await;
    let (_browser, tokens) = f.web_tokens(SCOPE, "ann@example.com").await;
    let claims = f
        .verify_jwt(tokens["id_token"].as_str().unwrap(), "web-app")
        .await;
    let sid: Uuid = claims["sid"].as_str().unwrap().parse().unwrap();
    let rt = tokens["refresh_token"].as_str().unwrap();

    // The same steps as `oidc::logout::end_session`.
    let txn = f.db.begin().await.unwrap();
    backchannel::queue(&txn, &f.config.master_key, f.tenant.id, Ended::Session(sid))
        .await
        .unwrap();
    let (refreshed, ()) = tokio::join!(f.refresh(rt, None), async {
        wait_for_lock_waiter(&f.db).await;
        refresh::revoke_by_session(&txn, f.tenant.id, sid)
            .await
            .unwrap();
        sessions::Entity::delete_by_id(sid)
            .exec(&txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();
    });
    assert_eq!(refreshed.0, StatusCode::BAD_REQUEST, "{:?}", refreshed.1);
    assert_eq!(refreshed.1["error"], "invalid_grant");
    assert_eq!(refreshed.1["error_description"], "refresh token revoked");
    assert_eq!(replay_alarms(&f).await, 0);
}

#[tokio::test]
async fn concurrent_logout_and_refresh_both_finish() {
    let f = Fixture::new().await;
    for round in 0..5 {
        let (mut browser, tokens) = f.web_tokens(SCOPE, "ann@example.com").await;
        let rt = tokens["refresh_token"].as_str().unwrap();
        let url = logout_url(tokens["id_token"].as_str().unwrap());
        let (logout, refreshed) = tokio::join!(browser.get(&url), f.refresh(rt, None));
        assert_eq!(logout.0, StatusCode::FOUND, "round {round}");
        assert!(
            matches!(refreshed.0, StatusCode::OK | StatusCode::BAD_REQUEST),
            "round {round}: {refreshed:?}"
        );
        assert!(!browser.has_session(), "round {round}");
    }
    assert_eq!(replay_alarms(&f).await, 0);
}

/// An admin action (revoke sessions, disable, password reset) as it starts:
/// the user row locked `FOR UPDATE` (`guard::lock_user`).
async fn admin_holding_user(f: &Fixture) -> DatabaseTransaction {
    let txn = f.db.begin().await.unwrap();
    users::Entity::find_by_id(f.user.id)
        .lock_exclusive()
        .one(&txn)
        .await
        .unwrap()
        .unwrap();
    txn
}

/// The rest of it: queue, delete the sessions, revoke the tokens.
async fn admin_revokes(f: &Fixture, txn: DatabaseTransaction) {
    wait_for_lock_waiter(&f.db).await;
    directory::revoke_credentials(&txn, &f.config.master_key, f.tenant.id, f.user.id, None)
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

/// With the session locked before the user, the refresh would hold the
/// session and its token row and wait on the user (new token's FK) while
/// the admin waits on the session: a deadlock.
#[tokio::test]
async fn refresh_waits_for_an_admin_holding_the_user() {
    let f = Fixture::new().await;
    let (_browser, tokens) = f.web_tokens(SCOPE, "ann@example.com").await;
    let rt = tokens["refresh_token"].as_str().unwrap();
    let txn = admin_holding_user(&f).await;
    let (refreshed, ()) = tokio::join!(f.refresh(rt, None), admin_revokes(&f, txn));
    assert_eq!(refreshed.0, StatusCode::BAD_REQUEST, "{:?}", refreshed.1);
    assert_eq!(refreshed.1["error"], "invalid_grant");
    assert_eq!(refreshed.1["error_description"], "refresh token revoked");
    assert_eq!(replay_alarms(&f).await, 0);
}

#[tokio::test]
async fn code_redemption_waits_for_an_admin_holding_the_user() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let url = authorize_url("web-app", WEB_CB, SCOPE, &[]);
    let code = browser.login_for_code(&url, "ann@example.com").await;
    let txn = admin_holding_user(&f).await;
    let redeem = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB);
    let (redeemed, ()) = tokio::join!(redeem, admin_revokes(&f, txn));
    assert_eq!(redeemed.0, StatusCode::BAD_REQUEST, "{:?}", redeemed.1);
    assert_eq!(redeemed.1["error"], "invalid_grant");
    assert_eq!(
        redeemed.1["error_description"],
        "the sign-in session has ended"
    );
}

/// My Account's "sign out everywhere" doesn't lock the user: two
/// revocations of the same sessions take them in id order.
#[tokio::test]
async fn concurrent_revocations_of_one_user_both_finish() {
    let f = Fixture::new().await;
    for _ in 0..4 {
        f.web_tokens(SCOPE, "ann@example.com").await;
    }
    let revoke = || async {
        let txn = f.db.begin().await.unwrap();
        directory::revoke_credentials(&txn, &f.config.master_key, f.tenant.id, f.user.id, None)
            .await
            .unwrap();
        txn.commit().await.unwrap();
    };
    tokio::join!(revoke(), revoke());
    let left = sessions::Entity::find()
        .filter(sessions::Column::UserId.eq(f.user.id))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

/// A sign-in replacing the browser's session locks that session (to queue
/// its logout) and inserts a new one for the user: with the session locked
/// before the user, an admin revocation holding the user deadlocks with it.
#[tokio::test]
async fn login_completion_waits_for_an_admin_holding_the_user() {
    let f = Fixture::new().await;
    let (mut browser, _) = f.web_tokens(SCOPE, "ann@example.com").await;
    let url = authorize_url("web-app", WEB_CB, SCOPE, &[("prompt", "login")]);
    let tx = browser.authorize(&url).await.unwrap();
    let (status, _, _) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    assert_eq!(status, StatusCode::OK);
    let txn = admin_holding_user(&f).await;
    let body = serde_json::json!({ "email": "ann@example.com", "password": PASSWORD });
    let ((status, resp), ()) =
        tokio::join!(browser.step(&tx, "password", body), admin_revokes(&f, txn));
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(
        resp["redirect"].as_str().unwrap().starts_with(WEB_CB),
        "{resp}"
    );
    // Signed in after the revocation: exactly the new session is left.
    let left = sessions::Entity::find()
        .filter(sessions::Column::UserId.eq(f.user.id))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(left, 1);
}

/// Device redemption locks the request row and inserts a session for its
/// user; deleting the user locks the user, then cascades to that row.
#[tokio::test]
async fn device_redemption_waits_for_a_user_deletion() {
    let f = Fixture::new().await;
    enable(&f, &f.spa).await;
    let (_, started) = start(&f, &f.spa, None, "openid offline_access").await;
    approve_as(
        &f,
        started["user_code"].as_str().unwrap(),
        "ann@example.com",
        true,
    )
    .await;
    let device_code = started["device_code"].as_str().unwrap();
    let txn = admin_holding_user(&f).await;
    let ((status, body), ()) = tokio::join!(poll(&f, &f.spa, None, device_code), async {
        wait_for_lock_waiter(&f.db).await;
        directory::revoke_credentials(&txn, &f.config.master_key, f.tenant.id, f.user.id, None)
            .await
            .unwrap();
        users::Entity::delete_by_id(f.user.id)
            .exec(&txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();
    });
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "unknown device_code");
}
