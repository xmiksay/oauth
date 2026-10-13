//! Own test binary: the Prometheus recorder is process-global.
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
    body::Body,
    http::{Request, StatusCode},
};
use oauth_server::{
    app::{self, AppState},
    metrics,
};
use sea_orm::DatabaseConnection;
use tower::ServiceExt;

#[tokio::test]
async fn requests_are_counted_with_bounded_labels() {
    let handle = metrics::install().unwrap();
    let app = app::router(
        AppState::new(
            DatabaseConnection::default(),
            common::test_config("postgres://unused"),
            true,
        ),
        common::no_web_dist(),
    );
    common::get(&app, "/healthz").await;
    common::get(&app, "/healthz").await;
    common::get(&app, "/acme/admin/users").await;
    common::get(&app, "/no/such/file.js").await;
    let custom = Request::builder()
        .method("XYZZY1")
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(custom).await.unwrap();

    metrics::login("success");
    metrics::token_issued("authorization_code", "jwt");
    metrics::token_error("invalid_grant");

    let (status, body) = common::get(&metrics::router(handle), "/metrics").await;
    assert!(
        body.contains(r#"oauth_logins_total{outcome="success"} 1"#),
        "{body}"
    );
    assert!(
        body.contains(r#"oauth_tokens_issued_total{grant="authorization_code",format="jwt"} 1"#),
        "{body}"
    );
    assert!(
        body.contains(r#"oauth_token_errors_total{error="invalid_grant"} 1"#),
        "{body}"
    );
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"http_requests_total{method="GET",path="/healthz",status="200"} 2"#),
        "{body}"
    );
    // Tenant slug must not become a label value.
    assert!(body.contains(r#"path="/{tenant}/admin/{*rest}""#), "{body}");
    assert!(!body.contains("acme"), "{body}");
    // Fallback traffic is recorded under one bounded path value.
    assert!(
        body.contains(r#"http_requests_total{method="GET",path="unmatched",status="404"} 1"#),
        "{body}"
    );
    assert!(!body.contains("file.js"), "{body}");
    // Extension methods collapse into "other".
    assert!(body.contains(r#"method="other""#), "{body}");
    assert!(!body.contains("XYZZY1"), "{body}");
    assert!(body.contains("http_request_duration_seconds"), "{body}");
}
