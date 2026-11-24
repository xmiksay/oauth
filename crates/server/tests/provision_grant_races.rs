// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `oauth apply` deleting an app while a device code redemption or an admin
//! consent grant for it runs (issue #98). Both lock their client and
//! resource apps (`backchannel::lock_apps`) before the device request /
//! consent row a delete of the app cascades to; the other way round they
//! hold that row while their FK check waits for the app apply deletes, and
//! apply's cascade waits for the row (40P01).
//!
//! Apply locks the doomed app, then waits for `extra-app` (created later, so
//! its id sorts after), which a test transaction holds `FOR KEY SHARE`. The
//! request starts, and once it waits too, the holder lets apply go on.
//! Also: an app the management API creates while apply runs stops it.

mod common;

use axum::http::StatusCode;
use common::{
    backchannel::{wait_for_lock_waiter, wait_for_lock_waiters},
    device,
    flow::Fixture,
    mgmt::{app_admin_token, app_by_client_id, post},
};
use entity::applications;
use oauth_server::provision::{self, Options, Report};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectionTrait, DatabaseTransaction, EntityTrait,
    QuerySelect, TransactionTrait,
};
use serde_json::{Value, json};
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

/// Holds `extra-app` `FOR KEY SHARE`, so apply's `FOR UPDATE` on it waits.
async fn hold_extra(f: &Fixture) -> DatabaseTransaction {
    let extra = app_by_client_id(&f.db, f.tenant.id, "extra-app").await;
    let holder = f.db.begin().await.unwrap();
    holder
        .execute_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT 1 FROM applications WHERE id = $1 FOR KEY SHARE",
            [extra.id.into()],
        ))
        .await
        .unwrap();
    holder
}

/// Runs `yaml` against `request`, started once apply waits for `extra-app`;
/// once the request waits too, `holder` commits.
async fn race<T>(
    f: &Fixture,
    yaml: &str,
    holder: DatabaseTransaction,
    request: impl Future<Output = T>,
) -> (Report, T) {
    let requesting = async {
        wait_for_lock_waiter(&f.db).await;
        let release = async {
            wait_for_lock_waiters(&f.db, 2).await;
            holder.commit().await.unwrap();
        };
        let (out, ()) = tokio::join!(request, release);
        out
    };
    let (report, out) = tokio::join!(apply(f, yaml), requesting);
    (
        report.expect("apply must not deadlock with the request"),
        out,
    )
}

fn assert_deleted(report: &Report, client_ids: &[&str]) {
    for id in client_ids {
        let line = format!("- application {id}");
        assert!(report.changes.contains(&line), "{report:#?}");
    }
}

#[tokio::test]
async fn a_device_code_redemption_racing_the_deletion_of_its_client_does_not_deadlock() {
    let f = Fixture::new().await;
    apply(
        &f,
        "tenant: contoso
applications:
  - { client_id: spa-app, display_name: Contoso SPA }
  - { client_id: extra-app, display_name: Extra }
",
    )
    .await
    .unwrap();
    device::enable(&f, &f.spa).await;
    let (status, start) = device::start(&f, &f.spa, None, "openid").await;
    assert_eq!(status, StatusCode::OK, "{start}");
    device::approve_as(
        &f,
        start["user_code"].as_str().unwrap(),
        "ann@example.com",
        true,
    )
    .await;
    let device_code = start["device_code"].as_str().unwrap();

    let holder = hold_extra(&f).await;
    // Apply holds `spa-app` for its delete: the redemption waits for it
    // before it locks the request (which the delete cascades to).
    let poll = device::poll(&f, &f.spa, None, device_code);
    let (report, (status, body)) = race(&f, "tenant: contoso\n", holder, poll).await;
    assert_deleted(&report, &["spa-app", "extra-app"]);
    // The client is gone: a plain refusal, not a deadlock's 500.
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");
    assert!(device::rows(&f).await.is_empty());
}

/// `web-app` requires `Api.Read` and `Api.Sync` of `api-app`; an admin has
/// granted it `Api.Read`. Returns the consent body widening that grant
/// (an upsert of the grant row, then a role assignment of `web-app`).
async fn consented(f: &Fixture) -> (String, Value) {
    apply(
        f,
        "tenant: contoso
applications:
  - client_id: web-app
    display_name: Contoso Web
    required_permissions:
      - { resource: api-app, type: delegated, value: Api.Read }
      - { resource: api-app, type: application, value: Api.Sync }
  - client_id: api-app
    display_name: API
    scopes: [{ value: Api.Read }]
    roles: [{ value: Api.Sync, display_name: Sync, allowed_member_types: [application] }]
  - { client_id: extra-app, display_name: Extra }
",
    )
    .await
    .unwrap();
    let api = app_by_client_id(&f.db, f.tenant.id, "api-app").await;
    let token = app_admin_token(f).await;
    let mut body = json!({
        "client_application_id": f.web.id,
        "resource_application_id": api.id,
        "scopes": ["Api.Read"],
        "app_roles": [],
    });
    let (status, granted) = post(f, &token, "/api/v1/consents", body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{granted}");
    body["app_roles"] = json!(["Api.Sync"]);
    (token, body)
}

const KEEP_API: &str = "tenant: contoso
applications:
  - client_id: api-app
    display_name: API
    scopes: [{ value: Api.Read }]
    roles: [{ value: Api.Sync, display_name: Sync, allowed_member_types: [application] }]
";

#[tokio::test]
async fn an_admin_consent_racing_the_deletion_of_its_client_does_not_deadlock() {
    let f = Fixture::new().await;
    let (token, body) = consented(&f).await;
    let holder = hold_extra(&f).await;
    // Apply holds `web-app` for its delete: the grant waits for it before
    // it upserts the grant row (which the delete cascades to).
    let grant = post(&f, &token, "/api/v1/consents", body);
    let (report, (status, body)) = race(&f, KEEP_API, holder, grant).await;
    assert_deleted(&report, &["web-app", "extra-app"]);
    // The client is gone: a body-named object that doesn't exist, not a 500.
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn an_admin_consent_racing_the_deletion_of_its_resource_does_not_deadlock() {
    let f = Fixture::new().await;
    let (token, body) = consented(&f).await;
    let holder = hold_extra(&f).await;
    // `api-app` sorts before `extra-app`: apply holds it for its delete.
    let grant = post(&f, &token, "/api/v1/consents", body);
    let keep_web = "tenant: contoso
applications:
  - { client_id: web-app, display_name: Contoso Web }
";
    let (report, (status, body)) = race(&f, keep_web, holder, grant).await;
    assert_deleted(&report, &["api-app", "extra-app"]);
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn apply_stops_on_a_declared_app_created_after_it_locked_the_apps() {
    let f = Fixture::new().await;
    // An admin holds `web-app` and creates the app the file declares; apply
    // lists the (still invisible) apps, then waits on `web-app`.
    let admin = f.db.begin().await.unwrap();
    applications::Entity::find_by_id(f.web.id)
        .lock_exclusive()
        .one(&admin)
        .await
        .unwrap();
    let mut late: applications::ActiveModel = f.spa.clone().into();
    late.id = Set(Uuid::now_v7());
    late.client_id = Set("late-app".into());
    late.insert(&admin).await.unwrap();
    let yaml = "tenant: contoso
applications:
  - { client_id: web-app, display_name: Contoso Web B }
  - { client_id: late-app, display_name: Late }
";
    let commit = async {
        wait_for_lock_waiter(&f.db).await;
        admin.commit().await.unwrap();
    };
    let (report, ()) = tokio::join!(apply(&f, yaml), commit);
    let err = format!("{:#}", report.unwrap_err());
    assert!(err.contains("created while apply ran"), "{err}");
    let web = applications::Entity::find_by_id(f.web.id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(web.display_name, f.web.display_name);
    assert!(!web.managed);
}
