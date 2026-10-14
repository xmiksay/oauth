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

/// [`migrate`], then [`builtin_apps::reconcile_all`] in the same locked
/// transaction, so replicas starting together never interleave rewrites and
/// nothing serves stale built-in redirect URIs once ready.
pub async fn migrate_and_reconcile(db: &DatabaseConnection, config: &Config) -> anyhow::Result<()> {
    let txn = begin_migrated(db).await?;
    let invalid = directory::invalid_enabled_slugs(&txn).await?;
    if !invalid.is_empty() {
        anyhow::bail!(
            "enabled tenants with slugs that are no longer valid host names: {}. \
             Rename them (UPDATE tenants SET slug = '<new>' WHERE slug = '<old>') or \
             disable them (UPDATE tenants SET disabled = true WHERE slug = '<old>'), \
             then start again",
            invalid.join(", ")
        );
    }
    let changed = builtin_apps::reconcile_all(&txn, config).await?;
    txn.commit().await.context("committing migrations")?;
    if changed > 0 {
        tracing::info!(changed, "rewrote built-in SPA redirect URIs");
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
