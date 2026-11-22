// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The management API shows `managed` on every kind `oauth apply` manages,
//! so an admin can tell what the next apply overwrites or deletes.

mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{app_by_client_id, call, mint_user_token, user_with_roles},
};
use entity::enums::DirectoryRole::GlobalAdmin;
use oauth_server::provision::{self, Options};
use serde_json::Value;

const FILE: &str = r"
tenant: contoso
users:
  - { email: alice@example.com, display_name: Alice }
applications:
  - client_id: stock
    display_name: Stock
    scopes:
      - { value: Stock.Read }
    roles:
      - { value: Stock.Admin, display_name: Admin, allowed_member_types: [user] }
  - client_id: till
    display_name: Till
    required_permissions:
      - { resource: stock, type: delegated, value: Stock.Read }
directory_roles:
  - { user: alice@example.com, role: UserAdmin }
role_assignments:
  - { resource: stock, role: Stock.Admin, user: alice@example.com }
admin_consents:
  - { client: till, resource: stock }
";

async fn items(f: &Fixture, token: &str, path: &str) -> Vec<Value> {
    let (st, body) = call(&f.app, Method::GET, path, Some(token), None).await;
    assert_eq!(st, StatusCode::OK, "{path}: {body}");
    body["items"].as_array().cloned().unwrap()
}

#[tokio::test]
async fn every_managed_kind_shows_the_marker() {
    let f = Fixture::new().await;
    let spec = provision::parse(FILE).unwrap();
    let none = |_: &str| None;
    provision::run(&f.db, &f.config, &spec, &Options { dry_run: false }, &none)
        .await
        .unwrap();
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let stock = app_by_client_id(&f.db, f.tenant.id, "stock").await.id;
    let till = app_by_client_id(&f.db, f.tenant.id, "till").await.id;

    let app = format!("/api/v1/applications/{stock}");
    let till_perms = format!("/api/v1/applications/{till}/required-permissions");
    let assignments = format!("/api/v1/role-assignments?resource_application_id={stock}");
    let consents = format!("/api/v1/consents?resource_application_id={stock}");
    for path in [
        format!("{app}/scopes"),
        format!("{app}/roles"),
        till_perms,
        assignments,
        consents,
    ] {
        let found = items(&f, &token, &path).await;
        assert_eq!(found.len(), 1, "{path}");
        assert_eq!(found[0]["managed"], true, "{path}");
    }

    // The GA's own role was assigned outside apply.
    let roles = items(&f, &token, "/api/v1/directory-roles").await;
    let managed: Vec<_> = roles
        .iter()
        .map(|r| (r["user_id"] == ga.id.to_string(), r["managed"].clone()))
        .collect();
    assert!(managed.contains(&(true, Value::Bool(false))), "{roles:?}");
    assert!(managed.contains(&(false, Value::Bool(true))), "{roles:?}");
}
