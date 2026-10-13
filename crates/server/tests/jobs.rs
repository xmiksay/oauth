// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Background jobs: key rotation and the TTL sweeper.
mod common;

use axum::http::StatusCode;
use chrono::Duration;
use common::{
    browser::authorize_url,
    flow::{Fixture, WEB_CB},
};
use entity::{
    authorization_codes, enums::KeyStatus, login_transactions, rate_limit_buckets, refresh_tokens,
    sessions, signing_keys,
};
use oauth_server::{
    authn::rate_limit,
    jobs::{self, rotation, sweeper},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, TransactionTrait,
};

async fn key_counts(f: &Fixture) -> (u64, u64, u64) {
    let count = |status| {
        signing_keys::Entity::find()
            .filter(signing_keys::Column::TenantId.eq(f.tenant.id))
            .filter(signing_keys::Column::Status.eq(status))
            .count(&f.db)
    };
    (
        count(KeyStatus::Next).await.unwrap(),
        count(KeyStatus::Active).await.unwrap(),
        count(KeyStatus::Retired).await.unwrap(),
    )
}

#[tokio::test]
async fn key_rotation_publishes_activates_and_retires() {
    let f = Fixture::new().await;
    let t0 = chrono::Utc::now().fixed_offset();
    // A token signed by the current keys before rotation.
    let mut browser = f.browser();
    let code = browser
        .login_for_code(
            &authorize_url("web-app", WEB_CB, "openid api://orders/Orders.Read", &[]),
            "ann@example.com",
        )
        .await;
    let (_, before) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;

    let report = rotation::run_once(&f.db, &f.config, t0 + Duration::days(87))
        .await
        .unwrap();
    assert_eq!(report, Some(rotation::Report::default()), "too early");
    let report = rotation::run_once(&f.db, &f.config, t0 + Duration::days(89))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.published, 2, "one next key per alg");
    assert_eq!(key_counts(&f).await, (2, 2, 0));
    let jwks = oauth_server::keys::jwks(&f.db, f.tenant.id).await.unwrap();
    assert_eq!(
        jwks["keys"].as_array().unwrap().len(),
        4,
        "next keys are pre-published"
    );
    // Re-running within the pre-publication window changes nothing.
    let report = rotation::run_once(&f.db, &f.config, t0 + Duration::days(90))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report, rotation::Report::default());

    let report = rotation::run_once(&f.db, &f.config, t0 + Duration::days(91))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.activated, 2);
    assert_eq!(key_counts(&f).await, (0, 2, 2));
    let retired = signing_keys::Entity::find()
        .filter(signing_keys::Column::Status.eq(KeyStatus::Retired))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    let ttl = retired.expires_at.unwrap() - retired.retired_at.unwrap();
    assert_eq!(ttl, Duration::hours(2), "max access TTL (1 h) + 1 h");

    // Old tokens still verify (retired key stays in JWKS); new ones use the new key.
    f.verify_jwt(before["access_token"].as_str().unwrap(), "api://orders")
        .await;
    f.verify_jwt(before["id_token"].as_str().unwrap(), "web-app")
        .await;
    let code = browser
        .login_for_code(
            &authorize_url("web-app", WEB_CB, "openid api://orders/Orders.Read", &[]),
            "ann@example.com",
        )
        .await;
    let (status, after) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(status, StatusCode::OK);
    let kid = |t: &serde_json::Value| {
        jsonwebtoken::decode_header(t.as_str().unwrap())
            .unwrap()
            .kid
    };
    assert_ne!(kid(&before["access_token"]), kid(&after["access_token"]));
    f.verify_jwt(after["access_token"].as_str().unwrap(), "api://orders")
        .await;

    // Another replica holding the lock makes this one skip.
    let holder = f.db.begin().await.unwrap();
    assert!(
        jobs::try_lock(&holder, jobs::ROTATION_LOCK_KEY)
            .await
            .unwrap()
    );
    let skipped = rotation::run_once(&f.db, &f.config, t0 + Duration::days(200))
        .await
        .unwrap();
    assert_eq!(skipped, None);
    holder.rollback().await.unwrap();
}

#[tokio::test]
async fn sweeper_deletes_expired_rows() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    // Leaves a session, a consumed code and a refresh token behind…
    let code = browser
        .login_for_code(
            &authorize_url("web-app", WEB_CB, "openid offline_access", &[]),
            "ann@example.com",
        )
        .await;
    f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    // …plus an abandoned login transaction and rate-limit buckets (password
    // step, /authorize and one made here).
    browser
        .authorize(&authorize_url(
            "web-app",
            WEB_CB,
            "openid",
            &[("prompt", "login")],
        ))
        .await
        .unwrap();
    let now = chrono::Utc::now();
    rate_limit::hit(&f.db, f.tenant.id, "ip:test", rate_limit::PER_IP, now)
        .await
        .unwrap()
        .unwrap();

    async fn counts(f: &Fixture) -> [u64; 5] {
        [
            login_transactions::Entity::find()
                .count(&f.db)
                .await
                .unwrap(),
            authorization_codes::Entity::find()
                .count(&f.db)
                .await
                .unwrap(),
            sessions::Entity::find().count(&f.db).await.unwrap(),
            refresh_tokens::Entity::find().count(&f.db).await.unwrap(),
            rate_limit_buckets::Entity::find()
                .count(&f.db)
                .await
                .unwrap(),
        ]
    }
    let before = counts(&f).await;
    assert_eq!(before[..4], [1, 1, 1, 1]);
    assert!(before[4] >= 3, "{before:?}");
    sweeper::run_once(&f.db).await.unwrap().unwrap();
    assert_eq!(counts(&f).await, before, "nothing expired yet");

    for table in [
        "login_transactions",
        "authorization_codes",
        "sessions",
        "refresh_tokens",
        "rate_limit_buckets",
    ] {
        f.db.execute_unprepared(&format!(
            "UPDATE {table} SET expires_at = now() - interval '1 second'"
        ))
        .await
        .unwrap();
    }
    let report = sweeper::run_once(&f.db).await.unwrap().unwrap();
    let swept: u64 = report.iter().map(|(_, n)| n).sum();
    assert_eq!(swept, before.iter().sum::<u64>(), "{report:?}");
    assert_eq!(counts(&f).await, [0, 0, 0, 0, 0]);
}
