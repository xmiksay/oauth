//! Outbox delivery, claim-then-send: a short transaction leases a batch of
//! due email messages (`attempts + 1`, `next_attempt_at = now + LEASE`),
//! then each is sent outside any transaction and its outcome recorded with
//! its own statement — sent (body dropped), retry after backoff
//! (`mail::outbox::next_attempt`) or dead (body dropped). A crash or
//! shutdown mid-batch leaves the unfinished rows leased: they are retried
//! once the lease runs out, never lost and never resent in a loop.
//!
//! The lease is the run's only claim on a row: a run never starts a send
//! that could outlast it, skips rows whose lease was taken over, and
//! records an outcome only while the row is still as it claimed it (same
//! `attempts` and `next_attempt_at`), so a run that lost its lease can't
//! overwrite the newer holder's state.
//!
//! Logs name the message id, kind and error kind only — never the
//! recipient, body or a token.

use std::time::Duration as StdDuration;

use anyhow::Context;
use chrono::{DateTime, Duration, FixedOffset};
use entity::{outbox, tenants};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    Statement, TransactionTrait,
    sea_query::{Condition, Expr, ExprTrait},
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::try_lock;
use crate::{
    config::Config,
    keys::wrap,
    mail::{Email, MailError, Mailer, outbox::next_attempt},
};

/// "oauthobx" in ASCII.
pub const OUTBOX_LOCK_KEY: i64 = 0x6f61_7574_686f_6278;
const BATCH: u64 = 8;
const SEND_SECS: i64 = 60;
const LEASE_SECS: i64 = 600;
/// Slack for clock skew between replicas: no send starts this close to the
/// end of the lease (on top of the send's own budget).
const MARGIN_SECS: i64 = 30;
// A whole batch of worst-case sends (plus the margin) must fit in its
// lease, or another replica could re-claim messages still being sent.
const _: () = assert!(BATCH as i64 * SEND_SECS + MARGIN_SECS < LEASE_SECS);
/// How long a claimed message is reserved for the run that claimed it.
pub const LEASE: Duration = Duration::seconds(LEASE_SECS);
/// Bounds one whole SMTP delivery (lettre's timeout is per command).
const SEND_TIMEOUT: StdDuration = StdDuration::from_secs(SEND_SECS.unsigned_abs());

/// The job's "now", read at every step (tests move it).
pub type Clock<'a> = &'a (dyn Fn() -> DateTime<FixedOffset> + Sync);

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub sent: u32,
    pub retrying: u32,
    pub dead: u32,
}

/// Leases up to [`BATCH`] due messages; `None` if another replica holds
/// the job lock. Each claim counts as an attempt.
pub async fn claim(
    db: &DatabaseConnection,
    now: DateTime<FixedOffset>,
) -> anyhow::Result<Option<Vec<outbox::Model>>> {
    let txn = db.begin().await.context("starting outbox claim")?;
    if !try_lock(&txn, OUTBOX_LOCK_KEY).await? {
        return Ok(None);
    }
    let rows = outbox::Entity::find()
        .from_raw_sql(Statement::from_sql_and_values(
            txn.get_database_backend(),
            r"UPDATE outbox SET attempts = attempts + 1, next_attempt_at = $2
              WHERE id IN (
                  SELECT id FROM outbox
                  WHERE channel = 'email' AND sent_at IS NULL AND dead_at IS NULL
                    AND next_attempt_at <= $1 AND expires_at > $1
                  ORDER BY next_attempt_at
                  LIMIT $3
                  FOR UPDATE SKIP LOCKED)
              RETURNING *",
            [now.into(), (now + LEASE).into(), BATCH.into()],
        ))
        .all(&txn)
        .await
        .context("claiming outbox messages")?;
    txn.commit().await.context("committing outbox claim")?;
    Ok(Some(rows))
}

fn email_of(
    config: &Config,
    row: &outbox::Model,
    tenants: &[tenants::Model],
) -> Result<Email, MailError> {
    let tenant = tenants
        .iter()
        .find(|t| t.id == row.tenant_id)
        .ok_or(MailError::Permanent)?;
    // Header text with control characters would make lettre panic; such a
    // message can never be sent.
    if (tenant.display_name.chars().chain(row.subject.chars())).any(char::is_control) {
        return Err(MailError::Permanent);
    }
    let sealed = row.body_enc.as_deref().ok_or(MailError::Permanent)?;
    let body = wrap::open(
        &config.master_key,
        &wrap::outbox_aad(row.tenant_id, row.id),
        sealed,
    )
    .map_err(|_| MailError::Permanent)?;
    let body = String::from_utf8(body.to_vec()).map_err(|_| MailError::Permanent)?;
    Ok(Email {
        from_name: tenant.display_name.clone(),
        to: row.recipient.clone(),
        subject: row.subject.clone(),
        body: Zeroizing::new(body),
    })
}

/// Sends one message, giving up (transient) after [`SEND_TIMEOUT`].
pub async fn send_bounded<M: Mailer>(mailer: &M, email: &Email) -> Result<(), MailError> {
    tokio::time::timeout(SEND_TIMEOUT, mailer.send(email))
        .await
        .unwrap_or(Err(MailError::Transient))
}

/// The claimed row, still exactly as this run leased it.
fn ours(row: &outbox::Model) -> Condition {
    Condition::all()
        .add(outbox::Column::Id.eq(row.id))
        .add(outbox::Column::Attempts.eq(row.attempts))
        .add(outbox::Column::NextAttemptAt.eq(row.next_attempt_at))
        .add(outbox::Column::SentAt.is_null())
        .add(outbox::Column::DeadAt.is_null())
}

async fn still_ours(db: &DatabaseConnection, row: &outbox::Model) -> anyhow::Result<bool> {
    let n = outbox::Entity::find()
        .filter(ours(row))
        .count(db)
        .await
        .context("checking outbox lease")?;
    Ok(n == 1)
}

/// Records an outcome only while this run still holds the lease; `false`
/// when it was lost (nothing written).
async fn record(
    db: &DatabaseConnection,
    row: &outbox::Model,
    update: outbox::ActiveModel,
) -> anyhow::Result<bool> {
    let result = outbox::Entity::update_many()
        .set(update)
        .filter(ours(row))
        .exec(db)
        .await
        .context("recording outbox delivery")?;
    Ok(result.rows_affected == 1)
}

/// Hands rows this run claimed but never tried back: due at `now`, the
/// claim's attempt undone — so a restart doesn't hold mail for a lease.
async fn release(
    db: &DatabaseConnection,
    rows: impl Iterator<Item = outbox::Model>,
    now: DateTime<FixedOffset>,
) -> anyhow::Result<()> {
    for row in rows {
        outbox::Entity::update_many()
            .col_expr(
                outbox::Column::Attempts,
                Expr::col(outbox::Column::Attempts).sub(1),
            )
            .col_expr(outbox::Column::NextAttemptAt, Expr::value(now))
            .filter(ours(&row))
            .exec(db)
            .await
            .context("releasing an untried outbox message")?;
    }
    Ok(())
}

/// Claims one batch and delivers it; `None` if another replica holds the
/// lock. Stops once `shutdown` fires or a send could outlast the lease,
/// releasing the rows it didn't get to.
pub async fn run_once<M: Mailer>(
    db: &DatabaseConnection,
    config: &Config,
    mailer: &M,
    clock: Clock<'_>,
    shutdown: &CancellationToken,
) -> anyhow::Result<Option<Report>> {
    let Some(claimed) = claim(db, clock()).await? else {
        return Ok(None);
    };
    let tenant_ids: Vec<_> = claimed.iter().map(|m| m.tenant_id).collect();
    let tenants = tenants::Entity::find()
        .filter(tenants::Column::Id.is_in(tenant_ids))
        .all(db)
        .await
        .context("loading outbox tenants")?;
    let mut report = Report::default();
    let mut rows = claimed.into_iter();
    while let Some(row) = rows.next() {
        // The claimed `next_attempt_at` is where our lease ends.
        let deadline = row.next_attempt_at - Duration::seconds(SEND_SECS + MARGIN_SECS);
        if shutdown.is_cancelled() || clock() >= deadline {
            release(db, std::iter::once(row).chain(rows), clock()).await?;
            break;
        }
        if !still_ours(db, &row).await? {
            tracing::warn!(message_id = %row.id, "outbox lease taken over; skipping");
            continue;
        }
        let result = match email_of(config, &row, &tenants) {
            Ok(email) => send_bounded(mailer, &email).await,
            Err(err) => Err(err),
        };
        let now = clock();
        let mut update = outbox::ActiveModel::default();
        let outcome = match result {
            Ok(()) => {
                update.sent_at = sea_orm::Set(Some(now));
                update.body_enc = sea_orm::Set(None);
                update.last_error = sea_orm::Set(None);
                &mut report.sent
            }
            Err(err) => {
                let retry = (err == MailError::Transient)
                    .then(|| next_attempt(row.attempts, now))
                    .flatten();
                update.last_error = sea_orm::Set(Some(err.kind().to_owned()));
                tracing::warn!(
                    message_id = %row.id, kind = row.kind, error = err.kind(),
                    attempts = row.attempts, dead = retry.is_none(),
                    "outbox delivery failed"
                );
                match retry {
                    Some(at) => {
                        update.next_attempt_at = sea_orm::Set(at);
                        &mut report.retrying
                    }
                    None => {
                        update.dead_at = sea_orm::Set(Some(now));
                        update.body_enc = sea_orm::Set(None);
                        &mut report.dead
                    }
                }
            }
        };
        if record(db, &row, update).await? {
            *outcome += 1;
        } else {
            tracing::warn!(message_id = %row.id, "outbox lease lost before recording");
        }
    }
    Ok(Some(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Hang;

    impl Mailer for Hang {
        async fn send(&self, _: &Email) -> Result<(), MailError> {
            std::future::pending().await
        }
    }

    // Paused clock: the 60 s timeout elapses instantly.
    #[tokio::test(start_paused = true)]
    async fn a_hanging_send_times_out_as_transient() {
        let email = Email {
            from_name: "T".into(),
            to: "a@b.c".into(),
            subject: "s".into(),
            body: Zeroizing::new(String::new()),
        };
        // The outer bound only turns a missing inner timeout into a failure
        // instead of a hang.
        let outcome = tokio::time::timeout(2 * SEND_TIMEOUT, send_bounded(&Hang, &email)).await;
        assert_eq!(outcome, Ok(Err(MailError::Transient)));
    }
}
