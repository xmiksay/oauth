//! Device authorization grant (RFC 8628) state: issuing the device / user
//! code pair, finding a pending request by its user code, recording the
//! user's decision and the device's polls. The protocol endpoints are
//! `oidc::device_authorization` / `oidc::device_grant`; the browser side
//! (code entry, sign-in, confirmation) is `authn::device_code` plus the
//! ordinary login transaction.

pub mod user_code;

use anyhow::Context;
use chrono::{DateTime, Duration, FixedOffset};
use entity::{device_authorizations, enums::DeviceStatus};
use sea_orm::{
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, QuerySelect, Statement,
    sea_query::{Expr, OnConflict},
};
use uuid::Uuid;

use crate::secret;

/// Lifetime of a device authorization (`expires_in`).
pub const TTL_SECS: i64 = 900;
/// Initial polling interval (`interval`).
pub const INTERVAL_SECS: i32 = 5;
/// RFC 8628 §3.5: every `slow_down` adds 5 s for all later polls.
pub const SLOW_DOWN_STEP_SECS: i32 = 5;
/// Cap of the growing interval (also a DB CHECK).
pub const MAX_INTERVAL_SECS: i32 = 60;
/// A poll may arrive this early (network jitter between two polls) and still
/// count as respecting the interval.
const POLL_SLACK_MS: i64 = 1000;
/// Attempts at drawing a user code unused in the tenant.
const USER_CODE_ATTEMPTS: usize = 4;

pub struct NewDevice {
    pub tenant_id: Uuid,
    pub client_app_id: Uuid,
    /// OIDC scopes plus the resource's scope values.
    pub scopes: Vec<String>,
    pub resource_app_id: Option<Uuid>,
}

/// The codes handed to the device (returned once, stored only hashed).
pub struct Issued {
    pub device_code: String,
    /// Display form `XXXX-XXXX`.
    pub user_code: String,
}

pub async fn issue(conn: &impl ConnectionTrait, new: NewDevice) -> anyhow::Result<Issued> {
    use device_authorizations::Column;
    let device_code = secret::random_token()?;
    let now = chrono::Utc::now().fixed_offset();
    for _ in 0..USER_CODE_ATTEMPTS {
        let code = user_code::generate()?;
        let row = device_authorizations::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(new.tenant_id),
            application_id: Set(new.client_app_id),
            device_code_hash: Set(secret::hash(&device_code)),
            user_code_hash: Set(user_code::hash(&code)),
            scopes: Set(new.scopes.clone()),
            resource_application_id: Set(new.resource_app_id),
            status: Set(DeviceStatus::Pending),
            interval_secs: Set(INTERVAL_SECS),
            expires_at: Set(now + Duration::seconds(TTL_SECS)),
            ..Default::default()
        };
        // A user code still held by another row of the tenant (live, or
        // expired but not yet swept) is drawn again.
        let inserted = device_authorizations::Entity::insert(row)
            .on_conflict(
                OnConflict::columns([Column::TenantId, Column::UserCodeHash])
                    .do_nothing()
                    .to_owned(),
            )
            .exec_without_returning(conn)
            .await;
        match inserted {
            Ok(1) => {
                return Ok(Issued {
                    device_code,
                    user_code: user_code::display(&code),
                });
            }
            Ok(_) | Err(DbErr::RecordNotInserted) => {}
            Err(err) => return Err(err).context("storing device authorization"),
        }
    }
    anyhow::bail!("no free user code after {USER_CODE_ATTEMPTS} attempts")
}

/// The live, still undecided request a (normalised) user code names.
pub async fn find_pending(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    code: &str,
) -> anyhow::Result<Option<device_authorizations::Model>> {
    let now = chrono::Utc::now().fixed_offset();
    Ok(device_authorizations::Entity::find()
        .filter(device_authorizations::Column::TenantId.eq(tenant_id))
        .filter(device_authorizations::Column::UserCodeHash.eq(user_code::hash(code)))
        .filter(device_authorizations::Column::Status.eq(DeviceStatus::Pending))
        .one(conn)
        .await
        .context("looking up user code")?
        .filter(|row| row.expires_at > now))
}

/// The request a device code names, row-locked (`FOR UPDATE`) when `lock`,
/// so polls, redemption and the decision serialize.
pub async fn by_device_code(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    device_code: &str,
    lock: bool,
) -> anyhow::Result<Option<device_authorizations::Model>> {
    let mut query = device_authorizations::Entity::find()
        .filter(device_authorizations::Column::TenantId.eq(tenant_id))
        .filter(device_authorizations::Column::DeviceCodeHash.eq(secret::hash(device_code)));
    if lock {
        query = query.lock_exclusive();
    }
    query.one(conn).await.context("looking up device code")
}

/// The signed-in user's answer.
pub enum Decision<'a> {
    Approve {
        /// The approving browser session; redemption needs it still live.
        session_id: Uuid,
        amr: &'a [String],
        auth_time: DateTime<FixedOffset>,
    },
    Deny,
}

/// Records `user_id`'s decision on a pending, unexpired request; `false` =
/// it was decided already, has expired or is gone (compare-and-set, so two
/// browsers can't both decide).
pub async fn decide(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    id: Uuid,
    user_id: Uuid,
    decision: Decision<'_>,
) -> anyhow::Result<bool> {
    use device_authorizations::Column;
    let now = chrono::Utc::now().fixed_offset();
    let mut update = device_authorizations::Entity::update_many()
        .col_expr(Column::UserId, Expr::value(user_id))
        .col_expr(Column::DecidedAt, Expr::value(now));
    update = match decision {
        Decision::Approve {
            session_id,
            amr,
            auth_time,
        } => update
            .col_expr(Column::Status, Expr::value(DeviceStatus::Approved))
            .col_expr(Column::ApprovedSessionId, Expr::value(session_id))
            .col_expr(Column::Amr, Expr::value(amr.to_vec()))
            .col_expr(Column::AuthTime, Expr::value(auth_time)),
        Decision::Deny => update.col_expr(Column::Status, Expr::value(DeviceStatus::Denied)),
    };
    let result = update
        .filter(Column::Id.eq(id))
        .filter(Column::TenantId.eq(tenant_id))
        .filter(Column::Status.eq(DeviceStatus::Pending))
        .filter(Column::ExpiresAt.gt(now))
        .exec(conn)
        .await
        .context("recording device authorization decision")?;
    Ok(result.rows_affected == 1)
}

/// Locks the approving session `FOR KEY SHARE` (so a sign-out or revocation
/// waits for a redemption that already holds it) and returns whether it is
/// still live. Lock order user → session → request: deleting the session
/// locks it and then, through the FK's `SET NULL`, the request row.
pub async fn lock_approving_session(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    session_id: Uuid,
) -> anyhow::Result<bool> {
    let row = conn
        .query_one_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            "WITH s AS (SELECT expires_at FROM sessions \
               WHERE tenant_id = $1 AND id = $2 FOR KEY SHARE) \
             SELECT EXISTS (SELECT 1 FROM s WHERE expires_at > now()) AS live",
            [tenant_id.into(), session_id.into()],
        ))
        .await
        .context("locking the approving session")?
        .context("locking the approving session returned no row")?;
    row.try_get::<bool>("", "live")
        .context("reading whether the approving session is live")
}

/// Denies every approved, not yet redeemed request of the user — on the
/// transaction that signs them out everywhere (`directory::revoke_credentials`),
/// so an approval can't outlive the revocation even when the approving
/// session itself is kept.
pub async fn deny_unredeemed(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<()> {
    use device_authorizations::Column;
    device_authorizations::Entity::update_many()
        .col_expr(Column::Status, Expr::value(DeviceStatus::Denied))
        .col_expr(Column::ApprovedSessionId, Expr::value(Option::<Uuid>::None))
        .filter(Column::TenantId.eq(tenant_id))
        .filter(Column::UserId.eq(user_id))
        .filter(Column::Status.eq(DeviceStatus::Approved))
        .filter(Column::ConsumedAt.is_null())
        .exec(conn)
        .await
        .context("denying the user's unredeemed device approvals")?;
    Ok(())
}

/// Whether a poll at `now` came sooner than `interval_secs` after the last
/// one (allowing [`POLL_SLACK_MS`] of jitter).
pub fn too_fast(
    last: Option<DateTime<FixedOffset>>,
    interval_secs: i32,
    now: DateTime<FixedOffset>,
) -> bool {
    last.is_some_and(|last| {
        let min_gap = i64::from(interval_secs) * 1000 - POLL_SLACK_MS;
        (now - last).num_milliseconds() < min_gap
    })
}

/// Records a poll of a pending request (row locked by the caller); `true`
/// = it came too fast and the interval grew (`slow_down`).
pub async fn record_poll(
    conn: &impl ConnectionTrait,
    row: &device_authorizations::Model,
    now: DateTime<FixedOffset>,
) -> anyhow::Result<bool> {
    use device_authorizations::Column;
    let slow_down = too_fast(row.last_polled_at, row.interval_secs, now);
    let interval = if slow_down {
        (row.interval_secs + SLOW_DOWN_STEP_SECS).min(MAX_INTERVAL_SECS)
    } else {
        row.interval_secs
    };
    device_authorizations::Entity::update_many()
        .col_expr(Column::LastPolledAt, Expr::value(now))
        .col_expr(Column::IntervalSecs, Expr::value(interval))
        .filter(Column::Id.eq(row.id))
        .exec(conn)
        .await
        .context("recording device poll")?;
    Ok(slow_down)
}

/// Marks an approved request redeemed (row locked by the caller).
pub async fn consume(conn: &impl ConnectionTrait, id: Uuid) -> anyhow::Result<()> {
    device_authorizations::Entity::update_many()
        .col_expr(
            device_authorizations::Column::ConsumedAt,
            Expr::current_timestamp(),
        )
        .filter(device_authorizations::Column::Id.eq(id))
        .exec(conn)
        .await
        .context("consuming device authorization")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(ms: i64) -> DateTime<FixedOffset> {
        DateTime::from_timestamp_millis(1_700_000_000_000 + ms)
            .unwrap()
            .fixed_offset()
    }

    #[test]
    fn first_poll_is_never_too_fast() {
        assert!(!too_fast(None, INTERVAL_SECS, at(0)));
    }

    #[test]
    fn interval_with_jitter_slack() {
        let last = Some(at(0));
        assert!(too_fast(last, 5, at(1_000)));
        assert!(too_fast(last, 5, at(3_999)));
        // Up to a second early still counts as on time.
        assert!(!too_fast(last, 5, at(4_000)));
        assert!(!too_fast(last, 5, at(5_000)));
        assert!(too_fast(last, 10, at(5_000)));
        assert!(!too_fast(last, 10, at(9_500)));
    }

    #[test]
    fn interval_constants_fit_the_db_check() {
        let steps = (MAX_INTERVAL_SECS - INTERVAL_SECS) / SLOW_DOWN_STEP_SECS;
        assert!(steps > 0);
        assert!((1..=60).contains(&INTERVAL_SECS) && (1..=60).contains(&MAX_INTERVAL_SECS));
    }
}
