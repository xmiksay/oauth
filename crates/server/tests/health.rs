// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use oauth_server::{
    app::{self, AppState},
    db,
};
use sea_orm::DatabaseConnection;

#[tokio::test]
async fn probes_against_real_database() {
    let pg = common::start_postgres().await;
    let conn = db::connect(&pg.url).await.unwrap();

    let state = AppState::new(conn, common::test_config(&pg.url), false);
    let app = app::router(state.clone(), common::no_web_dist());

    assert_eq!(common::get(&app, "/healthz").await.0, StatusCode::OK);
    // Not ready until startup migrations have run.
    let (status, body) = common::get(&app, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("temporarily_unavailable"), "{body}");

    db::migrate(&state.db).await.unwrap();
    state
        .migrated
        .store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(
        common::get(&app, "/readyz").await,
        (StatusCode::OK, "ok".into())
    );
}

#[tokio::test]
async fn readyz_fails_when_database_unreachable() {
    let app = app::router(
        AppState::new(
            DatabaseConnection::default(),
            common::test_config("postgres://unused"),
            true,
        ),
        common::no_web_dist(),
    );
    // Liveness must not depend on the database, or k8s restarts healthy pods
    // during a DB outage.
    assert_eq!(common::get(&app, "/healthz").await.0, StatusCode::OK);
    assert_eq!(
        common::get(&app, "/readyz").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}
