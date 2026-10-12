// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::{Router, http::StatusCode};
use oauth_server::spa;

fn dist_with_index() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("index.html"), "<!doctype html>SPA").expect("write index");
    std::fs::create_dir(dir.path().join("assets")).expect("mkdir assets");
    std::fs::write(dir.path().join("assets/app.js"), "console.log(1)").expect("write asset");
    dir
}

#[tokio::test]
async fn spa_areas_fall_back_to_index() {
    let dist = dist_with_index();
    let app: Router = spa::router(dist.path());
    for uri in [
        "/acme/login",
        "/acme/login/totp",
        "/system/admin",
        "/system/admin/apps/123/overview",
        "/acme/myaccount/sessions",
    ] {
        let (status, body) = common::get(&app, uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(body.contains("SPA"), "{uri}: {body}");
    }
}

#[tokio::test]
async fn static_assets_are_served_and_unknown_paths_404() {
    let dist = dist_with_index();
    let app: Router = spa::router(dist.path());
    assert_eq!(
        common::get(&app, "/assets/app.js").await,
        (StatusCode::OK, "console.log(1)".into())
    );
    // Only the three SPA areas get the history fallback.
    assert_eq!(
        common::get(&app, "/acme/oauth2/authorize").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        common::get(&app, "/assets/missing.js").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn missing_dist_serves_404_instead_of_crashing() {
    let app: Router = spa::router(common::no_web_dist());
    assert_eq!(
        common::get(&app, "/acme/login").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(common::get(&app, "/").await.0, StatusCode::NOT_FOUND);
}
