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
use sea_orm::{ConnectionTrait, DatabaseConnection, TransactionTrait};

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

    // Every `down` undoes its `up` cleanly (catches drop-order mistakes).
    Migrator::down(&conn, None).await.unwrap();
    assert_eq!(pending(&conn).await, Migrator::migrations().len());
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

/// The group-name uniqueness migration refuses existing duplicates (naming
/// them) instead of renaming anything, and applies once they're fixed.
#[tokio::test]
async fn duplicate_group_names_abort_the_migration() {
    let pg = common::start_postgres().await;
    let conn = db::connect(&pg.url).await.unwrap();
    db::migrate(&conn).await.unwrap();
    Migrator::down(&conn, Some(1)).await.unwrap();
    let pending_names: Vec<String> = Migrator::get_pending_migrations(&conn)
        .await
        .unwrap()
        .iter()
        .map(|m| m.name().to_owned())
        .collect();
    assert_eq!(pending_names, ["m20261121_000011_group_names"]);
    let tenant = uuid::Uuid::now_v7();
    let (a, b, other) = (
        uuid::Uuid::now_v7(),
        uuid::Uuid::now_v7(),
        uuid::Uuid::now_v7(),
    );
    conn.execute_unprepared(&format!(
        "INSERT INTO tenants (id, slug, display_name) VALUES ('{tenant}', 'fabrikam', 'F');
         INSERT INTO groups (id, tenant_id, display_name) VALUES
             ('{a}', '{tenant}', 'Ops'), ('{b}', '{tenant}', 'OPS'), ('{other}', '{tenant}', 'Dev');"
    ))
    .await
    .unwrap();

    let err = db::migrate(&conn).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("must be unique per tenant"), "{msg}");
    assert!(
        msg.contains("fabrikam") && msg.contains(&a.to_string()),
        "{msg}"
    );
    assert!(
        msg.contains(&b.to_string()) && !msg.contains("Dev"),
        "{msg}"
    );
    assert_eq!(pending(&conn).await, 1, "nothing applied, nothing renamed");

    conn.execute_unprepared(&format!(
        "UPDATE groups SET display_name = 'Ops 2' WHERE id = '{b}'"
    ))
    .await
    .unwrap();
    db::migrate(&conn).await.unwrap();
    assert_eq!(pending(&conn).await, 0);
    let dup = conn
        .execute_unprepared(&format!(
            "INSERT INTO groups (id, tenant_id, display_name) VALUES ('{}', '{tenant}', 'dEV')",
            uuid::Uuid::now_v7()
        ))
        .await;
    assert!(dup.is_err(), "the index enforces it from now on");
}
