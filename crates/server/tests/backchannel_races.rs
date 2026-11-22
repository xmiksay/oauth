// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! A logout racing a refresh of the same session: both lock the session
//! before its refresh tokens, so neither deadlocks, and the refresh that
//! loses is a plain `invalid_grant`, not a replay alarm.
mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{backchannel::logout_url, flow::Fixture};
use entity::{audit_events, sessions};
use oauth_server::{
    backchannel::{self, Ended},
    tokens::refresh,
};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, TransactionTrait};
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
        tokio::time::sleep(Duration::from_millis(500)).await;
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
