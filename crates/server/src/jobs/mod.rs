//! Background jobs, spawned by `serve` once migrations are applied. Every
//! run happens in a transaction that first takes
//! `pg_try_advisory_xact_lock(job key)`: with several replicas exactly one
//! does the work per tick, the others skip, and a crashed leader's lock is
//! released with its connection.

pub mod rotation;
pub mod sweeper;

use std::time::Duration;

use anyhow::Context;
use sea_orm::{ConnectionTrait, DatabaseTransaction, Statement};
use tokio::{task::JoinHandle, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::app::AppState;

/// "oauthswp" in ASCII.
pub const SWEEPER_LOCK_KEY: i64 = 0x6f61_7574_6873_7770;
/// "oauthrot" in ASCII.
pub const ROTATION_LOCK_KEY: i64 = 0x6f61_7574_6872_6f74;

const SWEEP_EVERY: Duration = Duration::from_secs(60);
const ROTATE_EVERY: Duration = Duration::from_secs(300);

/// `true` if this transaction now holds the job's leader lock.
pub async fn try_lock(txn: &DatabaseTransaction, key: i64) -> anyhow::Result<bool> {
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            txn.get_database_backend(),
            "SELECT pg_try_advisory_xact_lock($1) AS locked",
            [key.into()],
        ))
        .await
        .context("taking job lock")?
        .context("advisory lock query returned no row")?;
    row.try_get("", "locked").context("reading job lock result")
}

/// Runs both jobs on their intervals until `shutdown` fires. A run in
/// progress finishes first (each is a short transaction).
pub fn spawn(state: AppState, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut sweep = tokio::time::interval(SWEEP_EVERY);
        let mut rotate = tokio::time::interval(ROTATE_EVERY);
        sweep.set_missed_tick_behavior(MissedTickBehavior::Skip);
        rotate.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = sweep.tick() => {
                    if let Err(err) = sweeper::run_once(&state.db).await {
                        tracing::warn!(error = ?err, "TTL sweep failed");
                    }
                }
                _ = rotate.tick() => {
                    let now = chrono::Utc::now().fixed_offset();
                    if let Err(err) = rotation::run_once(&state.db, &state.config, now).await {
                        tracing::warn!(error = ?err, "key rotation failed");
                    }
                }
            }
        }
        tracing::info!("background jobs stopped");
    })
}
