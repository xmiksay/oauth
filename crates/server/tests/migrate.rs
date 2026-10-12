// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::time::Duration;

use migration::{Migrator, MigratorTrait};
use oauth_server::db;
use sea_orm::{DatabaseConnection, TransactionTrait};

async fn pending(conn: &DatabaseConnection) -> usize {
    Migrator::get_pending_migrations(conn)
        .await
        .expect("pending migrations")
        .len()
}

#[tokio::test]
async fn migrate_waits_for_lock_and_is_idempotent() {
    let pg = common::start_postgres().await;
    let conn = db::connect(&pg.url).await.unwrap();

    // Another "replica" holds the lock. A session-level lock (as an operator
    // might take by hand) and `migrate`'s xact lock share one key space, so
    // they must conflict. The transaction only pins the session.
    let holder = conn.begin().await.unwrap();
    common::advisory(&holder, "pg_advisory_lock").await;

    let waiting = tokio::spawn({
        let conn = conn.clone();
        async move { db::migrate(&conn).await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!waiting.is_finished(), "migrate ran without the lock");

    common::advisory(&holder, "pg_advisory_unlock").await;
    holder.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("migrate did not proceed after the lock was released")
        .unwrap()
        .unwrap();

    // A later restart is a no-op.
    db::migrate(&conn).await.unwrap();
    assert_eq!(pending(&conn).await, 0);
}

#[tokio::test]
async fn migrate_reports_unreachable_database() {
    let err = db::migrate(&DatabaseConnection::default())
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("migration transaction"),
        "{err:#}"
    );
}
