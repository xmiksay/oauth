// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{PUBLIC_URL, browser::send};
use oauth_server::{
    app::{self, AppState},
    directory::{self, NewTenant},
    spa,
};

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
        "/",
        "/login",
        "/login/totp",
        "/admin",
        "/admin/apps/123/overview",
        "/myaccount/sessions",
        "/logout",
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
    // Only `/` and the SPA areas get the history fallback.
    assert_eq!(
        common::get(&app, "/oauth2/authorize").await.0,
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
    assert_eq!(common::get(&app, "/login").await.0, StatusCode::NOT_FOUND);
    assert_eq!(common::get(&app, "/").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tenant_root_serves_the_portal_but_the_apex_still_redirects() {
    let (_pg, db, config) = common::migrated_db().await;
    let tenant = NewTenant {
        slug: "contoso",
        display_name: "Contoso",
    };
    directory::create_tenant(&db, &config, tenant)
        .await
        .unwrap();
    let dist = dist_with_index();
    let app = app::router(AppState::new(db, config, true), dist.path());

    let (status, body) = common::get(&app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("SPA"), "{body}");

    let apex = Request::get(format!("{PUBLIC_URL}/"))
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = send(&app, apex).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        headers.get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("https://system.id.example.test/admin")
    );
    let other = Request::get("/").header(header::HOST, "nope.id.example.test");
    let (status, _, _) = send(&app, other.body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unknown tenant host");
}
