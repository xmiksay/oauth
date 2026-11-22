// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! An authorization code dies with its session: redeeming it after a logout
//! fails, and a logout racing the redemption either makes it fail or sees
//! its client — revoking the refresh token and queueing the notification.
mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{
    backchannel::{queued, set_uri},
    browser::{Browser, authorize_url},
    flow::{Fixture, WEB_CB},
};
use entity::{refresh_tokens, sessions};
use oauth_server::{
    backchannel::{self, Ended},
    tokens::refresh,
};
use sea_orm::{ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter, TransactionTrait};
use serde_json::Value;
use uuid::Uuid;

const RP: &str = "https://rp.example/bcl";

/// A signed-in browser's unredeemed `openid offline_access` code and its
/// session id.
async fn code(f: &Fixture) -> (Browser, String, Uuid) {
    let mut browser = f.browser();
    let url = authorize_url("web-app", WEB_CB, "openid offline_access", &[]);
    let code = browser.login_for_code(&url, "ann@example.com").await;
    let sid = sessions::Entity::find()
        .filter(sessions::Column::UserId.eq(f.user.id))
        .all(&f.db)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .max()
        .unwrap();
    (browser, code, sid)
}

async fn redeem(f: &Fixture, code: &str) -> (StatusCode, Value) {
    f.redeem(&f.web, Some(&f.web_secret), code, WEB_CB).await
}

/// The first step of `oidc::logout::end_session`: the session locked.
async fn begin_logout(f: &Fixture, sid: Uuid) -> DatabaseTransaction {
    let txn = f.db.begin().await.unwrap();
    backchannel::queue(&txn, &f.config.master_key, f.tenant.id, Ended::Session(sid))
        .await
        .unwrap();
    txn
}

/// The rest of it: tokens revoked, session gone.
async fn finish_logout(f: &Fixture, txn: DatabaseTransaction, sid: Uuid) {
    refresh::revoke_by_session(&txn, f.tenant.id, sid)
        .await
        .unwrap();
    sessions::Entity::delete_by_id(sid)
        .exec(&txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

async fn session_tokens(f: &Fixture, sid: Uuid) -> Vec<refresh_tokens::Model> {
    refresh_tokens::Entity::find()
        .filter(refresh_tokens::Column::SessionId.eq(sid))
        .all(&f.db)
        .await
        .unwrap()
}

fn assert_refused(resp: &(StatusCode, Value)) {
    assert_eq!(resp.0, StatusCode::BAD_REQUEST, "{:?}", resp.1);
    assert_eq!(resp.1["error"], "invalid_grant");
}

#[tokio::test]
async fn a_code_dies_with_its_session() {
    let f = Fixture::new().await;
    set_uri(&f, Some(RP)).await;
    let (_browser, code, sid) = code(&f).await;
    let txn = begin_logout(&f, sid).await;
    finish_logout(&f, txn, sid).await;

    assert_refused(&redeem(&f, &code).await);
    assert!(session_tokens(&f, sid).await.is_empty());
    assert!(queued(&f).await.is_empty());
}

/// Logout first: it holds the session while the redemption starts, so the
/// redemption waits, then finds the session gone.
#[tokio::test]
async fn redemption_waits_for_a_logout_holding_the_session() {
    let f = Fixture::new().await;
    set_uri(&f, Some(RP)).await;
    let (_browser, code, sid) = code(&f).await;
    let txn = begin_logout(&f, sid).await;
    let (redeemed, ()) = tokio::join!(redeem(&f, &code), async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        finish_logout(&f, txn, sid).await;
    });
    assert_refused(&redeemed);
    assert!(session_tokens(&f, sid).await.is_empty());
    assert!(queued(&f).await.is_empty());
}

/// Redemption first: while its transaction holds the session (as the token
/// endpoint's does from the session check to commit), a logout waits, then
/// sees the recorded client and queues its notification.
#[tokio::test]
async fn logout_waits_for_a_redemption_holding_the_session() {
    let f = Fixture::new().await;
    set_uri(&f, Some(RP)).await;
    let (_browser, _code, sid) = code(&f).await;
    let redemption = f.db.begin().await.unwrap();
    assert!(
        backchannel::record_client(&redemption, f.tenant.id, sid, f.web.id)
            .await
            .unwrap()
    );
    let ((), ()) = tokio::join!(
        async {
            let txn = begin_logout(&f, sid).await;
            finish_logout(&f, txn, sid).await;
        },
        async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            redemption.commit().await.unwrap();
        }
    );
    let rows = queued(&f).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].recipient, f.web.id.to_string());
}

/// Real interleavings: whoever wins, no redeemed refresh token survives the
/// logout unannounced.
#[tokio::test]
async fn concurrent_logout_and_redemption_leave_no_silent_token() {
    let f = Fixture::new().await;
    set_uri(&f, Some(RP)).await;
    let mut redeemed_ok = 0;
    for round in 0..5 {
        let (_browser, code, sid) = code(&f).await;
        let (redeemed, ()) = tokio::join!(redeem(&f, &code), async {
            let txn = begin_logout(&f, sid).await;
            finish_logout(&f, txn, sid).await;
        });
        let tokens = session_tokens(&f, sid).await;
        if redeemed.0 == StatusCode::OK {
            redeemed_ok += 1;
            assert_eq!(tokens.len(), 1, "round {round}");
            assert!(
                tokens.iter().all(|t| t.revoked_at.is_some()),
                "round {round}"
            );
        } else {
            assert_refused(&redeemed);
            assert!(tokens.is_empty(), "round {round}");
        }
        assert_eq!(queued(&f).await.len(), redeemed_ok, "round {round}");
    }
}
