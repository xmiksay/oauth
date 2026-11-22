// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `retired_tenant_slugs` migration: renames that ran before the table
//! existed are backfilled from the system tenant's `tenant.rename` audit
//! events, and the schema keeps the table append-only and system-only.
mod common;

use entity::retired_tenant_slugs;
use migration::{Migrator, MigratorTrait};
use oauth_server::{
    db,
    directory::{self, NewTenant},
};
use sea_orm::{ConnectionTrait, DatabaseConnection, EntityTrait, QueryOrder};

use common::PUBLIC_URL;

const SYSTEM_ID: &str = "00000000-0000-7000-8000-000000000001";
const OTHER_ID: &str = "00000000-0000-7000-8000-000000000002";

async fn exec(conn: &DatabaseConnection, sql: &str) {
    conn.execute_unprepared(sql).await.expect(sql);
}

fn rename_event(tenant: &str, outcome: &str, from: &str, at: &str) -> String {
    format!(
        "INSERT INTO audit_events (id, tenant_id, at, actor_type, event_type, \
         target_type, target_id, outcome, details) VALUES (gen_random_uuid(), \
         '{tenant}', '{at}', 'system', 'tenant.rename', 'tenant', '{tenant}', \
         '{outcome}', jsonb_build_object('from', '{from}', 'to', 'root'))"
    )
}

#[tokio::test]
async fn earlier_renames_are_backfilled_from_the_audit_log() {
    let pg = common::start_postgres().await;
    let conn = db::connect(&pg.url).await.unwrap();
    let before = Migrator::migrations().len() - 1;
    Migrator::up(&conn, Some(u32::try_from(before).unwrap()))
        .await
        .unwrap();

    exec(
        &conn,
        &format!(
            "INSERT INTO tenants (id, slug, display_name, is_system) VALUES \
             ('{SYSTEM_ID}', 'root', 'System', true), ('{OTHER_ID}', 'other', 'Other', false)"
        ),
    )
    .await;
    for sql in [
        // Retired twice: one row, the first retirement's time.
        rename_event(SYSTEM_ID, "success", "config", "2026-01-01T00:00:00Z"),
        rename_event(SYSTEM_ID, "success", "config", "2026-03-01T00:00:00Z"),
        // Moved back to the slug it holds now: nothing to reserve.
        rename_event(SYSTEM_ID, "success", "root", "2026-02-01T00:00:00Z"),
        rename_event(SYSTEM_ID, "failure", "failed", "2026-01-01T00:00:00Z"),
        rename_event(SYSTEM_ID, "success", "Not A Slug", "2026-01-01T00:00:00Z"),
        // Only the system tenant's own log counts.
        rename_event(OTHER_ID, "success", "forged", "2026-01-01T00:00:00Z"),
    ] {
        exec(&conn, &sql).await;
    }

    Migrator::up(&conn, None).await.unwrap();

    let rows = retired_tenant_slugs::Entity::find()
        .order_by_asc(retired_tenant_slugs::Column::Slug)
        .all(&conn)
        .await
        .unwrap();
    let got: Vec<_> = rows
        .iter()
        .map(|r| {
            (
                r.slug.as_str(),
                r.tenant_id.to_string(),
                r.retired_at.to_rfc3339(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [(
            "config",
            SYSTEM_ID.to_owned(),
            "2026-01-01T00:00:00+00:00".to_owned()
        )]
    );

    let cfg = common::config_with(&pg.url, PUBLIC_URL, &[]).unwrap();
    let new = NewTenant {
        slug: "config",
        display_name: "Config",
    };
    let err = directory::create_tenant(&conn, &cfg, new)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("reserved"), "{err}");
}

#[tokio::test]
async fn the_table_is_append_only_and_system_only() {
    let pg = common::start_postgres().await;
    let conn = db::connect(&pg.url).await.unwrap();
    db::migrate(&conn).await.unwrap();
    exec(
        &conn,
        &format!(
            "INSERT INTO tenants (id, slug, display_name, is_system) VALUES \
             ('{SYSTEM_ID}', 'root', 'System', true), ('{OTHER_ID}', 'other', 'Other', false)"
        ),
    )
    .await;
    exec(
        &conn,
        &format!(
            "INSERT INTO retired_tenant_slugs (slug, tenant_id) VALUES ('config', '{SYSTEM_ID}')"
        ),
    )
    .await;

    for sql in [
        format!(
            "INSERT INTO retired_tenant_slugs (slug, tenant_id) VALUES ('stolen', '{OTHER_ID}')"
        ),
        "UPDATE retired_tenant_slugs SET slug = 'moved'".to_owned(),
        "DELETE FROM retired_tenant_slugs".to_owned(),
        "TRUNCATE retired_tenant_slugs".to_owned(),
        format!("DELETE FROM tenants WHERE id = '{SYSTEM_ID}'"),
    ] {
        assert!(conn.execute_unprepared(&sql).await.is_err(), "{sql}");
    }
    let slugs: Vec<_> = retired_tenant_slugs::Entity::find()
        .all(&conn)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.slug)
        .collect();
    assert_eq!(slugs, ["config"]);
}
