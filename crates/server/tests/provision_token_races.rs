// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `oauth apply` racing a token request (issue #98). The token path locks
//! its user `FOR KEY SHARE`, then inserts `session_clients` (and tokens),
//! whose FK takes the app `FOR KEY SHARE`. Apply takes every user lock
//! before it writes to or deletes an app, and locks declared apps only
//! `FOR NO KEY UPDATE`: taking them the other way round deadlocks (40P01).
//!
//! The race tests hold a token transaction's user lock, let apply run until
//! it waits for that user, then record the session's client and commit:
//! both sides must succeed. The last one shows a token request for a
//! declared app doesn't wait for a running apply at all, and the refresh
//! and sign-in ones that a real refresh / login completion blocked on an
//! app apply deletes waits before its token / login transaction row
//! (`backchannel::lock_apps`).

mod common;

use axum::http::StatusCode;
use common::{
    backchannel::{wait_for_lock_waiter, wait_for_lock_waiters},
    flow::Fixture,
};
use entity::{applications, sessions, users};
use oauth_server::{
    authn::session::{self, NewSession},
    backchannel, directory,
    provision::{self, Options, Report},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, TransactionTrait,
};
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

/// Ann and `web-app`, both adopted, so the racing apply leaves the app
/// unchanged (it only locks it).
const ADOPT: &str = "tenant: contoso
users:
  - { email: ann@example.com, display_name: Ann }
applications:
  - { client_id: web-app, display_name: Contoso Web }
";

/// A session of Ann (the fixture's user); returns its id.
async fn new_session(f: &Fixture) -> Uuid {
    let (session, _cookie) = session::create(
        &f.db,
        &f.config,
        NewSession {
            tenant_id: f.tenant.id,
            user_id: f.user.id,
            amr: &["pwd".to_owned()],
            auth_time: chrono::Utc::now().fixed_offset(),
            ip: None,
            user_agent: None,
            min_expires_at: None,
        },
    )
    .await
    .unwrap();
    session.id
}

/// Runs `yaml` while a code redemption for `web-app` in a session of Ann
/// holds her row: once apply waits for it, the redemption records its
/// client (an insert referencing the app) and commits.
async fn race(f: &Fixture, yaml: &str) -> Report {
    apply(f, ADOPT).await.unwrap();
    let session = new_session(f).await;
    let token = f.db.begin().await.unwrap();
    let lock = backchannel::lock_user(&token, f.tenant.id, f.user.id)
        .await
        .unwrap();
    assert!(lock.is_active());
    let redeeming = async {
        wait_for_lock_waiter(&f.db).await;
        let live = backchannel::record_client(&token, f.tenant.id, f.user.id, session, f.web.id)
            .await
            .expect("the token request must not deadlock with apply");
        assert!(live);
        token.commit().await.unwrap();
    };
    let (report, ()) = tokio::join!(apply(f, yaml), redeeming);
    report.expect("apply must not deadlock with the token request")
}

async fn sessions_of(f: &Fixture, user: &users::Model) -> u64 {
    sessions::Entity::find()
        .filter(sessions::Column::UserId.eq(user.id))
        .count(&f.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn disabling_a_user_while_a_declared_app_issues_to_them_does_not_deadlock() {
    let f = Fixture::new().await;
    let report = race(
        &f,
        "tenant: contoso
users:
  - { email: ann@example.com, display_name: Ann, disabled: true }
applications:
  - { client_id: web-app, display_name: Contoso Web }
",
    )
    .await;
    assert!(
        report
            .changes
            .iter()
            .any(|c| c.starts_with("~ user ann@example.com: disabled")),
        "{report:#?}"
    );
    let ann = directory::find_user_by_email(&f.db, f.tenant.id, "ann@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(ann.disabled);
    // The redemption finished first: disabling still ended its session.
    assert_eq!(sessions_of(&f, &ann).await, 0);
}

#[tokio::test]
async fn a_directory_role_while_a_declared_app_issues_does_not_deadlock() {
    let f = Fixture::new().await;
    let report = race(
        &f,
        "tenant: contoso
users:
  - { email: ann@example.com, display_name: Ann }
applications:
  - { client_id: web-app, display_name: Contoso Web }
directory_roles:
  - { user: ann@example.com, role: UserAdmin }
",
    )
    .await;
    assert!(
        report
            .changes
            .iter()
            .any(|c| c.starts_with("+ directory role ")),
        "{report:#?}"
    );
    assert_eq!(sessions_of(&f, &f.user).await, 1);
}

#[tokio::test]
async fn deleting_a_user_and_an_app_they_use_does_not_deadlock() {
    let f = Fixture::new().await;
    // Drops both: apply locks Ann (waiting for the redemption) before it
    // deletes `web-app`, never the other way round.
    let report = race(&f, "tenant: contoso\n").await;
    for line in ["- user ann@example.com", "- application web-app"] {
        assert!(report.changes.iter().any(|c| c == line), "{report:#?}");
    }
    assert!(
        directory::find_user_by_email(&f.db, f.tenant.id, "ann@example.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        applications::Entity::find_by_id(f.web.id)
            .one(&f.db)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_running_apply_does_not_stall_token_requests_for_its_apps() {
    let f = Fixture::new().await;
    apply(
        &f,
        "tenant: contoso
users:
  - { email: ann@example.com, display_name: Ann }
applications:
  - { client_id: web-app, display_name: Contoso Web }
  - { client_id: spa-app, display_name: Contoso SPA }
",
    )
    .await
    .unwrap();
    assert!(
        f.web.id < f.spa.id,
        "apply must lock web-app before it waits for spa-app"
    );
    let session = new_session(&f).await;
    // A redemption for `spa-app` holds it until apply, which drops it, waits
    // in its delete — by then apply has locked `web-app`.
    let holder = f.db.begin().await.unwrap();
    assert!(
        backchannel::record_client(&holder, f.tenant.id, f.user.id, session, f.spa.id)
            .await
            .unwrap()
    );
    let redeeming = async {
        wait_for_lock_waiter(&f.db).await;
        // A redemption for `web-app` meanwhile goes through at once.
        let token = f.db.begin().await.unwrap();
        token
            .execute_unprepared("SET LOCAL lock_timeout = '5s'")
            .await
            .unwrap();
        let live = backchannel::record_client(&token, f.tenant.id, f.user.id, session, f.web.id)
            .await
            .expect("a token request must not wait for apply's lock on its app");
        assert!(live);
        token.commit().await.unwrap();
        holder.commit().await.unwrap();
    };
    let (report, ()) = tokio::join!(apply(&f, ADOPT), redeeming);
    let report = report.unwrap();
    assert!(
        report.changes.iter().any(|c| c == "- application spa-app"),
        "{report:#?}"
    );
}

#[tokio::test]
async fn a_refresh_racing_the_deletion_of_its_client_does_not_deadlock() {
    let f = Fixture::new().await;
    // `extra-app` is created now, so its id sorts after `web-app`'s: apply
    // locks `web-app` for its delete, then waits for `extra-app`.
    apply(
        &f,
        "tenant: contoso
applications:
  - { client_id: web-app, display_name: Contoso Web }
  - { client_id: extra-app, display_name: Extra }
",
    )
    .await
    .unwrap();
    // The family's `session_clients` row exists, so the rotation's own
    // insert runs no FK check: only an explicit app lock puts the app
    // before the presented token's row lock.
    let (_browser, tokens) = f
        .web_tokens("openid offline_access", "ann@example.com")
        .await;
    let refresh_token = tokens["refresh_token"].as_str().unwrap().to_owned();
    let extra = applications::Entity::find()
        .filter(applications::Column::ClientId.eq("extra-app"))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    let holder = f.db.begin().await.unwrap();
    holder
        .execute_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT 1 FROM applications WHERE id = $1 FOR KEY SHARE",
            [extra.id.into()],
        ))
        .await
        .unwrap();
    let refreshing = async {
        wait_for_lock_waiter(&f.db).await;
        // Apply holds `web-app` for its delete: the refresh waits for it.
        let release = async {
            wait_for_lock_waiters(&f.db, 2).await;
            holder.commit().await.unwrap();
        };
        let (response, ()) = tokio::join!(f.refresh(&refresh_token, None), release);
        response
    };
    let (report, (status, body)) = tokio::join!(apply(&f, "tenant: contoso\n"), refreshing);
    let report = report.expect("apply must not deadlock with the refresh");
    for line in ["- application web-app", "- application extra-app"] {
        assert!(report.changes.iter().any(|c| c == line), "{report:#?}");
    }
    // The client is gone: a plain refusal, not a deadlock's 500.
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

#[tokio::test]
async fn a_sign_in_racing_the_deletion_of_its_client_does_not_deadlock() {
    let f = Fixture::new().await;
    // As above: apply locks `web-app` for its delete, then waits for
    // `extra-app`.
    apply(
        &f,
        "tenant: contoso
applications:
  - { client_id: web-app, display_name: Contoso Web }
  - { client_id: extra-app, display_name: Extra }
",
    )
    .await
    .unwrap();
    // A first sign-in stores the consent, so the password step below goes
    // straight to completion (claim the login transaction, issue the code).
    f.web_tokens("openid", "ann@example.com").await;
    let mut browser = f.browser();
    let url = common::browser::authorize_url("web-app", common::flow::WEB_CB, "openid", &[]);
    let tx = browser.authorize(&url).await.expect("login page");
    let (status, _, _) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    assert_eq!(status, StatusCode::OK);
    let extra = applications::Entity::find()
        .filter(applications::Column::ClientId.eq("extra-app"))
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    let holder = f.db.begin().await.unwrap();
    holder
        .execute_raw(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT 1 FROM applications WHERE id = $1 FOR KEY SHARE",
            [extra.id.into()],
        ))
        .await
        .unwrap();
    let signing_in = async {
        wait_for_lock_waiter(&f.db).await;
        // Apply holds `web-app` for its delete: completion waits for it
        // before it claims the login transaction (which the delete cascades
        // to), not while holding it.
        let release = async {
            wait_for_lock_waiters(&f.db, 2).await;
            holder.commit().await.unwrap();
        };
        let body =
            serde_json::json!({ "email": "ann@example.com", "password": common::flow::PASSWORD });
        let (response, ()) = tokio::join!(browser.step(&tx, "password", body), release);
        response
    };
    let (report, (status, body)) = tokio::join!(apply(&f, "tenant: contoso\n"), signing_in);
    let report = report.expect("apply must not deadlock with the sign-in");
    assert!(
        report.changes.iter().any(|c| c == "- application web-app"),
        "{report:#?}"
    );
    // The client (and with it the login transaction) is gone: no code, and
    // not a deadlock's 500.
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}
