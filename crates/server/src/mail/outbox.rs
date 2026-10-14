//! The outbox: messages are written on the caller's transaction (a rolled
//! back action sends nothing) and delivered by `jobs::outbox`.

use anyhow::Context;
use chrono::{DateTime, Duration, FixedOffset};
use entity::{enums::Channel, outbox};
use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use uuid::Uuid;

use super::templates::Rendered;
use crate::keys::wrap;

/// Delay before attempt `n + 1` after `n` failed attempts.
const BACKOFF_MINUTES: [i64; 5] = [1, 5, 30, 120, 360];
/// A message is given up ("dead") after this many failed attempts.
pub const MAX_ATTEMPTS: i32 = 8;

/// When to retry after `failed` attempts (`None` = give up).
pub fn next_attempt(failed: i32, now: DateTime<FixedOffset>) -> Option<DateTime<FixedOffset>> {
    if failed >= MAX_ATTEMPTS {
        return None;
    }
    let step = usize::try_from(failed.saturating_sub(1)).unwrap_or(0);
    let minutes = BACKOFF_MINUTES
        .get(step)
        .or(BACKOFF_MINUTES.last())
        .copied()
        .unwrap_or(360);
    Some(now + Duration::minutes(minutes))
}

pub struct NewMessage<'a> {
    pub tenant_id: Uuid,
    pub channel: Channel,
    pub recipient: &'a str,
    pub rendered: &'a Rendered,
    /// Undelivered after this long, the message is dropped (a link it
    /// carries has expired by then anyway).
    pub ttl: Duration,
}

/// Queues a message on `conn` — pass the action's transaction.
pub async fn enqueue(
    conn: &impl ConnectionTrait,
    master_key: &[u8; 32],
    msg: NewMessage<'_>,
) -> anyhow::Result<()> {
    let id = Uuid::now_v7();
    let sealed = wrap::seal(
        master_key,
        &wrap::outbox_aad(msg.tenant_id, id),
        msg.rendered.body.as_bytes(),
    )?;
    let now = chrono::Utc::now().fixed_offset();
    let row = outbox::ActiveModel {
        id: Set(id),
        tenant_id: Set(msg.tenant_id),
        channel: Set(msg.channel),
        recipient: Set(msg.recipient.to_owned()),
        kind: Set(msg.rendered.kind.clone()),
        subject: Set(msg.rendered.subject.clone()),
        body_enc: Set(Some(sealed)),
        attempts: Set(0),
        next_attempt_at: Set(now),
        expires_at: Set(now + msg.ttl),
        ..Default::default()
    };
    outbox::Entity::insert(row)
        .exec_without_returning(conn)
        .await
        .context("queueing outbox message")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_schedule_then_dead() {
        let now = chrono::Utc::now().fixed_offset();
        let delays: Vec<i64> = (1..MAX_ATTEMPTS)
            .map(|n| (next_attempt(n, now).unwrap() - now).num_minutes())
            .collect();
        assert_eq!(delays, [1, 5, 30, 120, 360, 360, 360]);
        assert_eq!(next_attempt(MAX_ATTEMPTS, now), None);
        assert_eq!(next_attempt(MAX_ATTEMPTS + 3, now), None);
    }
}
