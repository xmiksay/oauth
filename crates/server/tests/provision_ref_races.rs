// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `oauth apply` racing a management API delete of an app, user or group
//! the file refers to (issue #113). Apply locks the consent grants it may
//! write (`provision::grant_locks`) before it inserts rows pointing at those
//! referenced parents; the delete locks the parent, then cascades into the
//! grants (a group's delete: into a membership apply adopted). Unless apply
//! locks the referenced parents `FOR KEY SHARE` before the grants, its FK
//! check waits for the delete while the delete's cascade waits for apply
//! (40P01). These tests live apart from `provision_grant_races.rs` only to
//! keep both files under the 400-line cap.
//!
//! A test transaction holds the `Ledger.Read` scope row, which apply updates
//! right after it locked the grants. Once apply waits for it, the delete
//! starts; once the delete waits too, the holder lets apply go on.

mod common;

use axum::http::{Method, StatusCode};
use common::{
    backchannel::{wait_for_lock_waiter, wait_for_lock_waiters},
    flow::Fixture,
    mgmt::{app_admin_token, call, mint_user_token, user_with_roles},
};
use entity::{applications, enums::DirectoryRole, groups, users};
use oauth_server::{
    consent,
    provision::{self, Options, Report},
};
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, TransactionTrait};
use serde_json::Value;

async fn apply(f: &Fixture, yaml: &str) -> anyhow::Result<Report> {
    let spec = provision::parse(yaml).unwrap();
    provision::run(
        &f.db,
        &f.config,
        &spec,
        &Options { dry_run: false },
        &|_: &str| None,
    )
    .await
}

/// Runs `yaml` while a test transaction holds the `Ledger.Read` scope row;
/// `delete` starts once apply waits for it, and the holder commits once
/// the delete waits too.
async fn race(f: &Fixture, yaml: &str, token: &str, path: &str) -> (Report, StatusCode, Value) {
    let holder = f.db.begin().await.unwrap();
    holder
        .execute_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT 1 FROM app_scopes WHERE application_id = $1 AND value = 'Ledger.Read' \
             FOR UPDATE",
            [f.ledger.id.into()],
        ))
        .await
        .unwrap();
    let deleting = async {
        wait_for_lock_waiter(&f.db).await;
        let delete = call(&f.app, Method::DELETE, path, Some(token), None);
        let release = async {
            wait_for_lock_waiters(&f.db, 2).await;
            holder.commit().await.unwrap();
        };
        let (out, ()) = tokio::join!(delete, release);
        out
    };
    let (report, (status, body)) = tokio::join!(apply(f, yaml), deleting);
    let report = report.expect("apply must not deadlock with the delete");
    (report, status, body)
}

/// `ledger` declared with `Ledger.Read` described (apply's first write
/// after it locked the grants), then `tail`.
fn ledger_described(tail: &str) -> String {
    format!(
        "tenant: contoso
applications:
  - client_id: ledger
    display_name: Ledger
    scopes: [{{ value: Ledger.Read, description: Reads the ledger }}]
{tail}"
    )
}

#[tokio::test]
async fn apply_racing_the_deletion_of_a_referenced_app_does_not_deadlock() {
    let f = Fixture::new().await;
    // `orders` is neither declared nor managed; apply locks the existing
    // admin grant `web-app` → `orders` it declares, then adds a required
    // permission on `orders` (a FK reference to it).
    let read = vec!["Orders.Read".to_owned()];
    consent::store_grant(&f.db, f.tenant.id, f.web.id, f.orders.id, None, &read)
        .await
        .unwrap();
    let yaml = ledger_described(
        "  - client_id: web-app
    display_name: Contoso Web
    required_permissions: [{ resource: orders, type: delegated, value: Orders.Read }]
admin_consents:
  - { client: web-app, resource: orders }
",
    );
    let token = app_admin_token(&f).await;
    let path = format!("/api/v1/applications/{}", f.orders.id);
    let (report, status, body) = race(&f, &yaml, &token, &path).await;
    assert!(
        report.changes.iter().any(|c| c.contains("web-app")),
        "{report:#?}"
    );
    // The delete waited for apply to commit, then went through.
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let orders = applications::Entity::find_by_id(f.orders.id)
        .one(&f.db)
        .await
        .unwrap();
    assert!(orders.is_none());
}

async fn user_admin_token(f: &Fixture) -> String {
    let admin = user_with_roles(
        &f.db,
        f.tenant.id,
        "ua@example.com",
        &[DirectoryRole::UserAdmin],
    )
    .await;
    mint_user_token(&f.db, &f.config, &f.tenant, &admin).await
}

/// Ann has consented to `orders`; the file (both runs end with `users`)
/// drops its managed `Orders.Write`, so apply locks every grant of
/// `orders`, hers included, then assigns her a role (a FK reference to
/// her) while her deletion races it.
async fn race_user_delete(users: &str) {
    let f = Fixture::new().await;
    let first = ledger_described(&format!(
        "  - client_id: orders
    display_name: Orders
    scopes: [{{ value: Orders.Read }}, {{ value: Orders.Write }}]
{users}"
    ))
    .replace(", description: Reads the ledger", "");
    apply(&f, &first).await.unwrap();
    let read = vec!["Orders.Read".to_owned()];
    let ann = Some(f.user.id);
    consent::store_grant(&f.db, f.tenant.id, f.web.id, f.orders.id, ann, &read)
        .await
        .unwrap();
    let yaml = ledger_described(&format!(
        "  - client_id: orders
    display_name: Orders
    scopes: [{{ value: Orders.Read }}]
role_assignments:
  - {{ resource: orders, role: Orders.Approver, user: ann@example.com }}
{users}"
    ));
    let token = user_admin_token(&f).await;
    let path = format!("/api/v1/users/{}", f.user.id);
    let (report, status, body) = race(&f, &yaml, &token, &path).await;
    assert!(
        report.changes.iter().any(|c| c.contains("ann@example.com")),
        "{report:#?}"
    );
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let ann = users::Entity::find_by_id(f.user.id)
        .one(&f.db)
        .await
        .unwrap();
    assert!(ann.is_none());
}

#[tokio::test]
async fn apply_racing_the_deletion_of_a_referenced_user_does_not_deadlock() {
    race_user_delete("").await;
}

/// Ann is declared and, after the first run, managed and unchanged: apply
/// never writes her row before the role assignment's FK check.
#[tokio::test]
async fn apply_racing_the_deletion_of_a_declared_unchanged_user_does_not_deadlock() {
    race_user_delete("users: [{ email: ann@example.com, display_name: Test User }]\n").await;
}

/// The fixture's group, renamed to `name`, holds Ann as a manual member. A
/// first run adopts the group, so the racing one leaves its row unchanged;
/// it adopts the membership (a write to a row the group's delete cascades
/// into), then, after the grant locks, assigns the group a role (a FK
/// reference to it).
async fn race_group_delete(name: &str) {
    let f = Fixture::new().await;
    let mut group: groups::ActiveModel = groups::Entity::find_by_id(f.group)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap()
        .into();
    group.display_name = sea_orm::Set(name.to_owned());
    group.update(&f.db).await.unwrap();
    let adopt = format!("tenant: contoso\ngroups: [{{ display_name: {name} }}]\n");
    apply(&f, &adopt).await.unwrap();
    let yaml = format!(
        "tenant: contoso
applications:
  - client_id: ledger
    display_name: Ledger
    scopes: [{{ value: Ledger.Read, description: Reads the ledger }}]
    roles:
      - {{ value: Ledger.Auditor, display_name: Auditor, allowed_member_types: [user] }}
groups:
  - {{ display_name: {name}, members: [ann@example.com] }}
role_assignments:
  - {{ resource: ledger, role: Ledger.Auditor, group: {name} }}
"
    );
    let token = user_admin_token(&f).await;
    let path = format!("/api/v1/groups/{}", f.group);
    let (report, status, body) = race(&f, &yaml, &token, &path).await;
    let assigned = format!("Ledger.Auditor -> group {name}");
    assert!(
        report.changes.iter().any(|c| c.contains(&assigned)),
        "{report:#?}"
    );
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let group = groups::Entity::find_by_id(f.group)
        .one(&f.db)
        .await
        .unwrap();
    assert!(group.is_none());
}

#[tokio::test]
async fn apply_racing_the_deletion_of_a_declared_unchanged_group_does_not_deadlock() {
    race_group_delete("Approvers").await;
}

/// Rust's `to_lowercase` turns the final `Σ` into `ς`, Postgres' `lower()`
/// into `σ`: the up-front lock must match names the way the lookup does.
#[tokio::test]
async fn apply_racing_the_deletion_of_a_non_ascii_group_does_not_deadlock() {
    race_group_delete("ΟΜΑΣ").await;
}
