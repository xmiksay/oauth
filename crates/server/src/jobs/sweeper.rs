//! TTL sweeper: deletes expired login transactions, codes, sessions, tokens
//! and rate-limit buckets. Expired rows are already ignored by every reader;
//! this only bounds table growth.

use anyhow::Context;
use sea_orm::{ConnectionTrait, DatabaseConnection, TransactionTrait};

use super::{SWEEPER_LOCK_KEY, try_lock};

/// Tables with an `expires_at` column, swept in this order.
const TABLES: [&str; 6] = [
    "login_transactions",
    "authorization_codes",
    "sessions",
    "refresh_tokens",
    "opaque_access_tokens",
    "rate_limit_buckets",
];

/// Rows deleted per table; `None` if another replica holds the lock.
pub async fn run_once(db: &DatabaseConnection) -> anyhow::Result<Option<Vec<(&'static str, u64)>>> {
    let txn = db.begin().await.context("starting sweep transaction")?;
    if !try_lock(&txn, SWEEPER_LOCK_KEY).await? {
        return Ok(None);
    }
    let mut report = Vec::with_capacity(TABLES.len());
    for table in TABLES {
        // Table names come from the constant above, never from input.
        let result = txn
            .execute_unprepared(&format!("DELETE FROM {table} WHERE expires_at < now()"))
            .await
            .with_context(|| format!("sweeping {table}"))?;
        report.push((table, result.rows_affected()));
    }
    txn.commit().await.context("committing sweep")?;
    let total: u64 = report.iter().map(|(_, n)| n).sum();
    if total > 0 {
        tracing::info!(?report, "swept expired rows");
    }
    Ok(Some(report))
}
