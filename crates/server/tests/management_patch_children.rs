// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! PATCH of `me`, app scopes and app roles: values equal to the stored ones
//! are no change — 200 with the object, no write, no audit event.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{app_admin_token, audited, call, mint_user_token, post},
};
use entity::{app_roles, users};
use sea_orm::EntityTrait;
use serde_json::{Value, json};
use uuid::Uuid;

const APPS: &str = "/api/v1/applications";

async fn patch(f: &Fixture, token: &str, path: &str, body: Value) -> (StatusCode, Value) {
    call(&f.app, Method::PATCH, path, Some(token), Some(&body)).await
}

/// A fresh confidential app of `f`'s tenant; returns its id and path.
async fn new_app(f: &Fixture, token: &str) -> (Uuid, String) {
    let (st, app) = post(f, token, APPS, json!({ "display_name": "Orders" })).await;
    assert_eq!(st, StatusCode::CREATED, "{app}");
    let id: Uuid = app["id"].as_str().unwrap().parse().unwrap();
    (id, format!("{APPS}/{id}"))
}

#[tokio::test]
async fn me_display_name_echo_is_no_change() {
    let f = Fixture::new().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let me = "/api/v1/me";
    let before = users::Entity::find_by_id(f.user.id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();

    // Same name (surrounding spaces are normalised away): no write, no event.
    let echo = json!({ "display_name": format!("  {}  ", before.display_name) });
    let (st, body) = patch(&f, &token, me, echo).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["display_name"], before.display_name.as_str());
    let after = users::Entity::find_by_id(f.user.id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.updated_at, before.updated_at, "nothing written");
    assert!(
        audited(&f.db, "user.profile_update", f.user.id)
            .await
            .is_empty()
    );

    let (st, body) = patch(&f, &token, me, json!({ "display_name": "Renamed" })).await;
    assert_eq!(
        (st, body["display_name"].as_str()),
        (StatusCode::OK, Some("Renamed"))
    );
    let events = audited(&f.db, "user.profile_update", f.user.id).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["fields"], json!(["display_name"]));
}

#[tokio::test]
async fn scope_echo_is_no_change() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let (app_id, app) = new_app(&f, &token).await;
    let create = json!({ "value": "Orders.Read", "description": "Read orders" });
    let (_, scope) = post(&f, &token, &format!("{app}/scopes"), create).await;
    let path = format!("{app}/scopes/{}", scope["id"].as_str().unwrap());

    let echo = json!({ "description": "Read orders", "admin_consent_required": false });
    let (st, body) = patch(&f, &token, &path, echo).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(
        audited(&f.db, "application.scope_update", app_id)
            .await
            .is_empty()
    );

    let change = json!({ "description": "Read orders", "admin_consent_required": true });
    let (st, body) = patch(&f, &token, &path, change).await;
    assert_eq!(
        (st, body["admin_consent_required"].as_bool()),
        (StatusCode::OK, Some(true))
    );
    assert_eq!(
        audited(&f.db, "application.scope_update", app_id)
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn role_echo_is_no_change_even_reordered() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let (app_id, app) = new_app(&f, &token).await;
    let create = json!({
        "value": "Orders.Admin",
        "display_name": "Orders admin",
        "description": "Manage orders",
        "allowed_member_types": ["user", "application"],
    });
    let (_, role) = post(&f, &token, &format!("{app}/roles"), create).await;
    let path = format!("{app}/roles/{}", role["id"].as_str().unwrap());

    // The member types are a set: a different order is the same value.
    let echo = json!({
        "display_name": "Orders admin",
        "description": "Manage orders",
        "allowed_member_types": ["application", "user"],
    });
    let (st, body) = patch(&f, &token, &path, echo).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(
        audited(&f.db, "application.role_update", app_id)
            .await
            .is_empty()
    );

    let change = json!({ "display_name": "Order admins", "allowed_member_types": ["user"] });
    let (st, body) = patch(&f, &token, &path, change).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["allowed_member_types"], json!(["user"]));
    assert_eq!(
        audited(&f.db, "application.role_update", app_id)
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn role_member_types_are_stored_in_canonical_order() {
    let f = Fixture::new().await;
    let token = app_admin_token(&f).await;
    let (_, app) = new_app(&f, &token).await;
    let body = json!({
        "value": "Orders.Both",
        "display_name": "Both",
        "allowed_member_types": ["application", "user"],
    });
    let (st, role) = post(&f, &token, &format!("{app}/roles"), body).await;
    assert_eq!(st, StatusCode::CREATED, "{role}");
    assert_eq!(role["allowed_member_types"], json!(["user", "application"]));
    let id: Uuid = role["id"].as_str().unwrap().parse().unwrap();
    let stored = app_roles::Entity::find_by_id(id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.allowed_member_types, ["user", "application"]);
}
