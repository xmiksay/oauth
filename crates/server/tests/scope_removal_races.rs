// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Removing a resource scope racing a multi-resource refresh (issue #106).
//! The refresh locks its consent rows `FOR SHARE`, then the presented
//! refresh token (`mark_rotated`). A scope removal rewrites consent rows and
//! revokes the refresh tokens carrying the scope: it must write every consent
//! row before it revokes any token, or it holds the token while it waits for
//! the consent (40P01, a 500 or a failed apply).
//!
//! A test transaction holds the refresh's session `FOR UPDATE`, so the
//! refresh stops between its consent lock and its token lock. The removal
//! starts, and once it waits too (for the consent row), the holder lets the
//! refresh go on: both must succeed, and the refresh's new token is revoked.

mod common;

use axum::http::{Method, StatusCode};
use common::{
    backchannel::{wait_for_lock_waiter, wait_for_lock_waiters},
    flow::Fixture,
    mgmt::{app_admin_token, call},
    mrrt::{LEDGER, error, live_ledger_tokens},
};
use entity::{app_scopes, sessions};
use oauth_server::{
    consent,
    provision::{self, Options, Report},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryFilter, TransactionTrait,
};
use serde_json::Value;
use uuid::Uuid;

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

/// A `web-app` refresh token of Ann for `Orders.Read Orders.Write` (her own
/// consent: web-app → orders, both values).
async fn orders_rw_token(f: &Fixture) -> String {
    let (_, tokens) = f
        .web_tokens(
            "openid offline_access api://orders/Orders.Read api://orders/Orders.Write",
            "ann@example.com",
        )
        .await;
    tokens["refresh_token"].as_str().unwrap().to_owned()
}

/// A tenant-wide (admin) grant `web-app` → `resource`, not managed by apply.
async fn admin_grant(f: &Fixture, resource: Uuid, value: &str) {
    let values = [value.to_owned()];
    consent::store_grant(&f.db, f.tenant.id, f.web.id, resource, None, &values)
        .await
        .unwrap();
}

/// Holds Ann's (only) session `FOR UPDATE`: a refresh in it stops at
/// `backchannel::record_client`, after its consent lock and before its
/// token lock.
async fn hold_session(f: &Fixture) -> DatabaseTransaction {
    let session = sessions::Entity::find()
        .filter(sessions::Column::UserId.eq(f.user.id))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    let holder = f.db.begin().await.unwrap();
    holder
        .execute_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT 1 FROM sessions WHERE id = $1 FOR UPDATE",
            [session.id.into()],
        ))
        .await
        .unwrap();
    holder
}

/// Refreshes `rt` for `scope` while `removal` runs: the refresh first, held
/// after its consent lock; `removal` once the refresh waits; the refresh let
/// go once `removal` waits too.
async fn race<R>(
    f: &Fixture,
    rt: &str,
    scope: &str,
    removal: impl Future<Output = R>,
) -> ((StatusCode, Value), R) {
    let holder = hold_session(f).await;
    let removing = async {
        wait_for_lock_waiter(&f.db).await;
        let release = async {
            wait_for_lock_waiters(&f.db, 2).await;
            holder.commit().await.unwrap();
        };
        let (out, ()) = tokio::join!(removal, release);
        out
    };
    tokio::join!(f.refresh(rt, Some(scope)), removing)
}

/// The family is revoked: the rotated token is refused.
async fn assert_family_revoked(f: &Fixture, body: &Value) {
    let rotated = body["refresh_token"].as_str().unwrap();
    let reply = f.refresh(rotated, None).await;
    assert_eq!(
        error(&reply),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
}

const ADOPT: &str = "tenant: contoso
applications:
  - client_id: orders
    display_name: Orders
    scopes: [{ value: Orders.Read }, { value: Orders.Write }, { value: Orders.Manage }]
  - client_id: web-app
    display_name: Contoso Web
    required_permissions: [{ resource: ledger, type: delegated, value: Ledger.Read }]
";

/// Drops `Orders.Write` (consent writes, then its tokens) and adopts the
/// admin grant web-app → ledger (a consent write the refresh holds up).
const DROP_WRITE: &str = "tenant: contoso
applications:
  - client_id: orders
    display_name: Orders
    scopes: [{ value: Orders.Read }, { value: Orders.Manage }]
  - client_id: web-app
    display_name: Contoso Web
    required_permissions: [{ resource: ledger, type: delegated, value: Ledger.Read }]
admin_consents:
  - { client: web-app, resource: ledger }
";

#[tokio::test]
async fn apply_removing_a_scope_racing_a_multi_resource_refresh_does_not_deadlock() {
    let f = Fixture::new().await;
    apply(&f, ADOPT).await.unwrap();
    let rt = orders_rw_token(&f).await;
    admin_grant(&f, f.ledger.id, "Ledger.Read").await;
    // The refresh (orders family → ledger) holds the ledger grant; apply
    // waits for it when it adopts that grant.
    let ((status, body), report) = race(&f, &rt, LEDGER, apply(&f, DROP_WRITE)).await;
    let report = report.expect("apply must not deadlock with the refresh");
    for line in [
        "- scope orders/Orders.Write",
        "~ admin consent web-app -> ledger: adopted",
    ] {
        assert!(report.changes.iter().any(|c| c == line), "{report:#?}");
    }
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope"], LEDGER, "{body}");
    // The removal saw what the refresh issued: the orders family, and the
    // ledger token minted from it, are revoked.
    assert_eq!(live_ledger_tokens(&f).await, 0);
    assert_family_revoked(&f, &body).await;
}

#[tokio::test]
async fn deleting_a_scope_through_the_api_racing_a_multi_resource_refresh_does_not_deadlock() {
    let f = Fixture::new().await;
    let rt = orders_rw_token(&f).await;
    // More of the family's own resource: a multi-resource refresh, which
    // locks Ann's grant (holding `Orders.Write`) and this admin grant.
    admin_grant(&f, f.orders.id, "Orders.Manage").await;
    let write = app_scopes::Entity::find()
        .filter(app_scopes::Column::ApplicationId.eq(f.orders.id))
        .filter(app_scopes::Column::Value.eq("Orders.Write"))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    let token = app_admin_token(&f).await;
    let path = format!("/api/v1/applications/{}/scopes/{}", f.orders.id, write.id);
    let delete = call(&f.app, Method::DELETE, &path, Some(&token), None);
    let manage = "api://orders/Orders.Manage";
    let ((status, body), (deleted, reply)) = race(&f, &rt, manage, delete).await;
    assert_eq!(deleted, StatusCode::NO_CONTENT, "{reply}");
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope"], manage, "{body}");
    assert_family_revoked(&f, &body).await;
}

/// web-app requires `Orders.Read` + `Orders.Manage` and holds the admin
/// consent for both: the admin grant is older than Ann's own grant.
const ADMIN_ORDERS: &str = "tenant: contoso
applications:
  - client_id: orders
    display_name: Orders
    scopes: [{ value: Orders.Read }, { value: Orders.Write }, { value: Orders.Manage }]
  - client_id: web-app
    display_name: Contoso Web
    required_permissions:
      - { resource: orders, type: delegated, value: Orders.Read }
      - { resource: orders, type: delegated, value: Orders.Manage }
admin_consents:
  - { client: web-app, resource: orders }
";

/// Drops `Orders.Write` (only in Ann's grant), then the required permission
/// `Orders.Read`, then narrows the admin consent to `Orders.Manage`.
const NARROW: &str = "tenant: contoso
applications:
  - client_id: orders
    display_name: Orders
    scopes: [{ value: Orders.Read }, { value: Orders.Manage }]
  - client_id: web-app
    display_name: Contoso Web
    required_permissions: [{ resource: orders, type: delegated, value: Orders.Manage }]
admin_consents:
  - { client: web-app, resource: orders, scopes: [Orders.Manage] }
";

/// Issue #109: apply writes consent rows in several statements. Removing a
/// scope rewrote (and locked) Ann's grant; narrowing the admin consent then
/// locked the older admin grant. A refresh holding the admin grant
/// `FOR SHARE` while it waits for Ann's grant deadlocked with it. Apply now
/// locks every grant it may write up front, in id order.
#[tokio::test]
async fn apply_narrowing_an_admin_consent_after_a_scope_removal_does_not_deadlock() {
    let f = Fixture::new().await;
    apply(&f, ADMIN_ORDERS).await.unwrap();
    let rt = orders_rw_token(&f).await;
    // Holds the required permission `Orders.Read`, which apply deletes
    // after its scope removal and before its admin consent write.
    let holder = f.db.begin().await.unwrap();
    holder
        .execute_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT 1 FROM app_required_permissions WHERE scope_id = (\
               SELECT id FROM app_scopes WHERE application_id = $1 AND value = 'Orders.Read') \
             FOR UPDATE",
            [f.orders.id.into()],
        ))
        .await
        .unwrap();
    let applying = apply(&f, NARROW);
    let refreshing = async {
        wait_for_lock_waiter(&f.db).await;
        let release = async {
            wait_for_lock_waiters(&f.db, 2).await;
            holder.commit().await.unwrap();
        };
        let (reply, ()) = tokio::join!(f.refresh(&rt, Some("api://orders/Orders.Manage")), release);
        reply
    };
    let (report, (status, body)) = tokio::join!(applying, refreshing);
    let report = report.expect("apply must not deadlock with the refresh");
    for line in [
        "- scope orders/Orders.Write",
        "- admin consent web-app -> orders",
    ] {
        assert!(report.changes.iter().any(|c| c == line), "{report:#?}");
    }
    assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
}
