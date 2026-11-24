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
//! declared app doesn't wait for a running apply at all.

mod common;

use common::{backchannel::wait_for_lock_waiter, flow::Fixture};
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
