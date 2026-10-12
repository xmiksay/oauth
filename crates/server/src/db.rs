//! Database connection and startup migrations.

use std::time::Duration;

use anyhow::Context;
use migration::{Migrator, MigratorTrait};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Statement, TransactionTrait,
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
    txn.commit().await.context("committing migrations")
}
