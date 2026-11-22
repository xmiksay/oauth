//! Database connection and startup migrations.

use std::time::Duration;

use anyhow::Context;
use migration::{Migrator, MigratorTrait};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction, Statement,
    TransactionTrait,
};

use crate::{
    config::Config,
    directory::{self, builtin_apps},
};

/// Arbitrary but fixed advisory-lock key ("oauthmig" in ASCII) shared by every
/// replica, so only one of them runs migrations at a time.
pub const MIGRATION_LOCK_KEY: i64 = 0x6f61_7574_686d_6967;

pub async fn connect(url: &str) -> anyhow::Result<DatabaseConnection> {
    let mut opts = ConnectOptions::new(url);
    opts.max_connections(20)
        .connect_timeout(Duration::from_secs(10))
        .sqlx_logging(false);
    Database::connect(opts)
        .await
        .context("connecting to the database")
}

/// Applies pending migrations inside one transaction holding a
/// transaction-scoped advisory lock. The lock lives exactly as long as the
/// transaction (released on commit, rollback or dropped connection), so it can
/// neither leak nor be taken on a different pooled session than the DDL.
pub async fn migrate(db: &DatabaseConnection) -> anyhow::Result<()> {
    let txn = begin_migrated(db).await?;
    txn.commit().await.context("committing migrations")
}

/// [`migrate`], then the system tenant's slug
/// ([`directory::reconcile_system_slug`]: refuse a mismatch, or rename with
/// `SYSTEM_TENANT_RENAME=1`), the `APEX_TENANT` check
/// ([`directory::ensure_apex_tenant`]) and [`builtin_apps::reconcile_all`] in the same
/// locked transaction, so replicas starting together never interleave
/// rewrites and nothing serves stale built-in redirect URIs once ready.
pub async fn migrate_and_reconcile(db: &DatabaseConnection, config: &Config) -> anyhow::Result<()> {
    let txn = begin_migrated(db).await?;
    // Before the slug check and redirect URI rewrite: both see the new slug.
    directory::reconcile_system_slug(&txn, config, directory::SlugVia::Startup).await?;
    let invalid = directory::invalid_enabled_slugs(&txn, &config.system_tenant_slug).await?;
    if !invalid.is_empty() {
        anyhow::bail!(
            "enabled tenants with slugs that are no longer valid host names or are retired \
             system tenant slugs: {}. \
             Rename them (UPDATE tenants SET slug = '<new>' WHERE slug = '<old>') or \
             disable them (UPDATE tenants SET disabled = true WHERE slug = '<old>'), \
             then start again",
            invalid.join(", ")
        );
    }
    directory::ensure_apex_tenant(&txn, config).await?;
    let changed = builtin_apps::reconcile_all(&txn, config).await?;
    txn.commit().await.context("committing migrations")?;
    if changed > 0 {
        tracing::info!(changed, "rewrote built-in SPA redirect URIs");
    }
    Ok(())
}

/// Errors unless every migration of this binary is applied: `oauth apply`
/// writes the schema it was built for and must not migrate itself (a dry
/// run changes nothing), so on an older database it stops before any write
/// instead of failing halfway on a missing column.
pub async fn ensure_migrated(conn: &impl ConnectionTrait) -> anyhow::Result<()> {
    const HINT: &str = "run `oauth serve` or `oauth bootstrap` first to migrate it";
    let backend = conn.get_database_backend();
    let exists = conn
        .query_one_raw(Statement::from_string(
            backend,
            "SELECT to_regclass('seaql_migrations') IS NOT NULL AS present",
        ))
        .await
        .context("checking the schema version")?
        .map(|row| row.try_get::<bool>("", "present"))
        .transpose()?
        .unwrap_or(false);
    if !exists {
        anyhow::bail!("the database has no schema yet: {HINT}");
    }
    let applied: std::collections::HashSet<String> = conn
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT version FROM seaql_migrations",
        ))
        .await
        .context("checking the schema version")?
        .iter()
        .map(|row| row.try_get::<String>("", "version"))
        .collect::<Result<_, _>>()?;
    let pending = Migrator::migrations()
        .iter()
        .filter(|m| !applied.contains(m.name()))
        .count();
    if pending > 0 {
        anyhow::bail!("the database schema is {pending} migration(s) behind: {HINT}");
    }
    Ok(())
}

async fn begin_migrated(db: &DatabaseConnection) -> anyhow::Result<DatabaseTransaction> {
    let txn = db.begin().await.context("starting migration transaction")?;
    txn.execute_raw(Statement::from_sql_and_values(
        txn.get_database_backend(),
        "SELECT pg_advisory_xact_lock($1)",
        [MIGRATION_LOCK_KEY.into()],
    ))
    .await
    .context("acquiring migration lock")?;
    Migrator::up(&txn, None)
        .await
        .context("running migrations")?;
    Ok(txn)
}
