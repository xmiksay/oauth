// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! MFA policy settings over the management API.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{app_by_client_id, audited, call, mint_user_token, user_with_roles},
};
use entity::enums::DirectoryRole::{ApplicationAdmin, GlobalAdmin};
use serde_json::{Value, json};

const SETTINGS: &str = "/api/v1/settings";

async fn patch(f: &Fixture, token: &str, path: &str, body: Value) -> (StatusCode, Value) {
    call(&f.app, Method::PATCH, path, Some(token), Some(&body)).await
}

#[tokio::test]
async fn global_admins_set_the_tenant_policy() {
    let f = Fixture::new().await;
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ga = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let (st, settings) = call(&f.app, Method::GET, SETTINGS, Some(&ga), None).await;
    assert_eq!(
        (st, settings["mfa_policy"].as_str()),
        (StatusCode::OK, Some("optional"))
    );
    let (st, body) = patch(&f, &ga, SETTINGS, json!({ "mfa_policy": "sometimes" })).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    let (st, body) = patch(&f, &ga, SETTINGS, json!({ "mfa_policy": "required" })).await;
    assert_eq!(
        (st, body["mfa_policy"].as_str()),
        (StatusCode::OK, Some("required"))
    );
    let logged = audited(&f.db, "tenant.update", f.tenant.id).await;
    assert_eq!(logged[0]["fields"], json!(["mfa_policy"]));
    // Echoing the unchanged value changes (and audits) nothing.
    patch(&f, &ga, SETTINGS, json!({ "mfa_policy": "required" })).await;
    assert_eq!(audited(&f.db, "tenant.update", f.tenant.id).await.len(), 1);
}

#[tokio::test]
async fn apps_can_only_tighten_the_policy() {
    let f = Fixture::new().await;
    let admin = user_with_roles(&f.db, f.tenant.id, "aa@example.com", &[ApplicationAdmin]).await;
    let admin = mint_user_token(&f.db, &f.config, &f.tenant, &admin).await;
    let path = format!("/api/v1/applications/{}", f.web.id);
    let (st, app) = call(&f.app, Method::GET, &path, Some(&admin), None).await;
    assert_eq!(
        (st, app["mfa_policy"].as_str()),
        (StatusCode::OK, Some("inherit"))
    );
    let (st, _) = patch(&f, &admin, &path, json!({ "mfa_policy": "optional" })).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, app) = patch(&f, &admin, &path, json!({ "mfa_policy": "required" })).await;
    assert_eq!(
        (st, app["mfa_policy"].as_str()),
        (StatusCode::OK, Some("required"))
    );
    let logged = audited(&f.db, "application.update", f.web.id).await;
    assert_eq!(logged[0]["fields"], json!(["mfa_policy"]));
    // Built-in apps take it too, from a GlobalAdmin.
    let portal = app_by_client_id(&f.db, f.tenant.id, "admin-portal").await;
    let path = format!("/api/v1/applications/{}", portal.id);
    let (st, _) = patch(&f, &admin, &path, json!({ "mfa_policy": "required" })).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ga = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let (st, app) = patch(&f, &ga, &path, json!({ "mfa_policy": "required" })).await;
    assert_eq!(
        (st, app["mfa_policy"].as_str()),
        (StatusCode::OK, Some("required"))
    );
}
