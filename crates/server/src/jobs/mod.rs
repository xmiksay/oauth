//! Background jobs, spawned by `serve` once migrations are applied. Every
//! run happens in a transaction that first takes
//! `pg_try_advisory_xact_lock(job key)`: with several replicas exactly one
//! does the work per tick, the others skip, and a crashed leader's lock is
//! released with its connection.

pub mod outbox;
pub mod rotation;
pub mod sweeper;

use std::{future::Future, sync::Arc, time::Duration};

use anyhow::Context;
use sea_orm::{ConnectionTrait, DatabaseTransaction, Statement};
use tokio::{task::JoinHandle, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::{app::AppState, mail::SmtpMailer};

/// "oauthswp" in ASCII.
pub const SWEEPER_LOCK_KEY: i64 = 0x6f61_7574_6873_7770;
/// "oauthrot" in ASCII.
pub const ROTATION_LOCK_KEY: i64 = 0x6f61_7574_6872_6f74;

const SWEEP_EVERY: Duration = Duration::from_secs(60);
const ROTATE_EVERY: Duration = Duration::from_secs(300);
const OUTBOX_EVERY: Duration = Duration::from_secs(10);

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

/// Awaits `job` on its own task, so a panic in one run is logged instead
/// of ending the loop (and with it every other job).
pub async fn guarded<F>(name: &'static str, job: F)
where
    F: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    match tokio::spawn(job).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::warn!(job = name, error = ?err, "background job run failed"),
        Err(join) => {
            tracing::error!(
                job = name,
                panicked = join.is_panic(),
                "background job run aborted"
            );
        }
    }
}

/// Runs the jobs on their intervals until `shutdown` fires (the outbox per
/// channel only when that channel is configured). A run in progress
/// finishes first.
pub fn spawn(state: AppState, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut sweep = tokio::time::interval(SWEEP_EVERY);
        let mut rotate = tokio::time::interval(ROTATE_EVERY);
        let mut deliver = tokio::time::interval(OUTBOX_EVERY);
        for interval in [&mut sweep, &mut rotate, &mut deliver] {
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        }
        let hello = state.config.public_url.host().to_owned();
        let mailer = match state
            .config
            .smtp
            .as_ref()
            .map(|smtp| SmtpMailer::new(smtp, &hello))
            .transpose()
        {
            Ok(mailer) => mailer.map(Arc::new),
            Err(err) => {
                tracing::error!(error = ?err, "SMTP setup failed; email is not delivered");
                None
            }
        };
        loop {
            let st = state.clone();
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = sweep.tick() => {
                    guarded("sweeper", async move { sweeper::run_once(&st.db).await.map(drop) }).await;
                }
                _ = rotate.tick() => {
                    guarded("rotation", async move {
                        let now = chrono::Utc::now().fixed_offset();
                        rotation::run_once(&st.db, &st.config, now).await.map(drop)
                    })
                    .await;
                }
                _ = deliver.tick() => {
                    if let Some(mailer) = mailer.clone() {
                        guarded("outbox", deliver_once(st.clone(), mailer, shutdown.clone())).await;
                    }
                    if let Some(bot) = st.telegram.clone() {
                        let bot = Arc::new(bot);
                        guarded("outbox_telegram", deliver_once(st, bot, shutdown.clone())).await;
                    }
                }
            }
        }
        tracing::info!("background jobs stopped");
    })
}

/// One outbox run of `courier`'s channel on the wall clock.
async fn deliver_once<C: outbox::Courier + 'static>(
    st: AppState,
    courier: Arc<C>,
    stop: CancellationToken,
) -> anyhow::Result<()> {
    let clock = || chrono::Utc::now().fixed_offset();
    outbox::run_once(&st.db, &st.config, courier.as_ref(), &clock, &stop)
        .await
        .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_panicking_run_is_contained() {
        guarded("test", async { panic!("boom") }).await;
        guarded("test", async { Err(anyhow::anyhow!("failed")) }).await;
        // Still here: the caller's loop goes on with the next job.
    }
}
