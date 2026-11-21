// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `web_origins` through the management API: create, update, validation,
//! audit, effect on CORS, and built-in apps kept fixed.
mod common;

use axum::http::{Method, StatusCode, header};
use common::{
    cors::{SPA_ORIGIN, assert_cors, fixture, request},
    mgmt::{app_admin_token, call},
};
use serde_json::json;

#[tokio::test]
async fn web_origins_through_the_management_api() {
    let f = fixture().await;
    let token = app_admin_token(&f).await;
    let path = format!("/api/v1/applications/{}", f.spa.id);
    let patch = |body| {
        let (app, path, token) = (f.app.clone(), path.clone(), token.clone());
        async move { call(&app, Method::PATCH, &path, Some(&token), Some(&body)).await }
    };
    let (st, app) = patch(json!({ "web_origins": ["https://spa2.example:8443"] })).await;
    assert_eq!(st, StatusCode::OK, "{app}");
    assert_eq!(app["web_origins"], json!(["https://spa2.example:8443"]));
    assert_eq!(
        app["effective_web_origins"],
        json!(["https://spa2.example:8443", SPA_ORIGIN, "http://127.0.0.1"])
    );
    let audit = common::mgmt::audited(&f.db, "application.update", f.spa.id).await;
    assert_eq!(audit.last().unwrap()["fields"], json!(["web_origins"]));
    let (_, headers) = request(
        &f,
        Method::GET,
        "/discovery/keys",
        &[(header::ORIGIN, "https://spa2.example:8443")],
        None,
    )
    .await;
    assert_cors(&headers, Some("https://spa2.example:8443"), "new origin");

    for bad in [
        json!({ "web_origins": ["https://a.example/"] }),
        json!({ "web_origins": ["https://*.example"] }),
        json!({ "web_origins": ["http://a.example"] }),
        json!({ "web_origins": ["https://A.example"] }),
        json!({ "web_origins": ["https://a.example:443"] }),
        json!({ "web_origins": ["https://a.example", "https://a.example"] }),
    ] {
        let (st, body) = patch(bad.clone()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }

    // Create takes them too and validates them the same way.
    let create = |web_origins| {
        let (app, token) = (f.app.clone(), token.clone());
        async move {
            let body = json!({
                "display_name": "New SPA",
                "client_type": "public",
                "redirect_uris": ["https://new.example/cb"],
                "web_origins": web_origins,
            });
            call(
                &app,
                Method::POST,
                "/api/v1/applications",
                Some(&token),
                Some(&body),
            )
            .await
        }
    };
    let (st, app) = create(json!(["https://extra.example"])).await;
    assert_eq!(st, StatusCode::CREATED, "{app}");
    assert_eq!(app["web_origins"], json!(["https://extra.example"]));
    assert_eq!(
        app["effective_web_origins"],
        json!(["https://extra.example", "https://new.example"])
    );
    let (st, body) = create(json!(["https://extra.example/"])).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");

    // Built-in apps keep theirs fixed.
    let builtin = common::mgmt::app_by_client_id(&f.db, f.tenant.id, "admin-portal").await;
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        &format!("/api/v1/applications/{}", builtin.id),
        Some(&token),
        Some(&json!({ "web_origins": [SPA_ORIGIN] })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}
