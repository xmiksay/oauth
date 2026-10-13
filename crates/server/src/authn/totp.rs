//! TOTP (RFC 6238: HMAC-SHA-1, 6 digits, 30 s steps, ±1 step skew) with
//! HMAC from AWS-LC. SHA-1 is what every authenticator app implements; HMAC
//! use of SHA-1 is not affected by its collision weakness. Secrets are
//! sealed with `OAUTH_MASTER_KEY` (`keys::wrap::totp_aad`); enrollment lives
//! in the `me` API (`api::me_mfa`) and calls [`seal_secret`] / [`store`].

use anyhow::Context;
use aws_lc_rs::hmac;
use entity::user_totp;
use sea_orm::{
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    sea_query::{Condition, Expr, ExprTrait, OnConflict},
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::keys::wrap;

pub const STEP_SECS: u64 = 30;
pub const DIGITS: u32 = 6;
/// Accepted clock skew in steps on either side.
const SKEW: i64 = 1;

/// HOTP (RFC 4226 §5.3) value for a counter.
pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let mac = tag.as_ref();
    let offset = usize::from(mac.last().copied().unwrap_or(0) & 0x0f);
    let word = mac
        .get(offset..offset + 4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_be_bytes);
    (word & 0x7fff_ffff) % 10u32.pow(DIGITS)
}

/// The matching time step for `code` at `now_unix`, if any is newer than
/// `last_used_step` (replay protection).
pub fn verify_code(
    secret: &[u8],
    code: &str,
    now_unix: u64,
    last_used_step: Option<i64>,
) -> Option<i64> {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = code.parse().ok()?;
    let current = i64::try_from(now_unix / STEP_SECS).ok()?;
    (current - SKEW..=current + SKEW)
        .filter(|step| last_used_step.is_none_or(|last| *step > last))
        .find(|step| u64::try_from(*step).is_ok_and(|s| hotp(secret, s) == wanted))
}

pub fn seal_secret(
    master_key: &[u8; 32],
    tenant_id: Uuid,
    user_id: Uuid,
    secret: &[u8],
) -> anyhow::Result<Vec<u8>> {
    wrap::seal(master_key, &wrap::totp_aad(tenant_id, user_id), secret)
}

pub fn open_secret(
    master_key: &[u8; 32],
    row: &user_totp::Model,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    wrap::open(
        master_key,
        &wrap::totp_aad(row.tenant_id, row.user_id),
        &row.secret_enc,
    )
    .context("unsealing TOTP secret")
}

/// Stores a user's sealed TOTP secret in one statement, replacing only an
/// UNCONFIRMED (pending) one — so a racing enrollment can never silently
/// swap out an active factor. `false` = a confirmed enrollment exists.
pub async fn store(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
    secret_enc: Vec<u8>,
    confirmed: bool,
) -> anyhow::Result<bool> {
    let now = chrono::Utc::now().fixed_offset();
    let row = user_totp::ActiveModel {
        user_id: Set(user_id),
        tenant_id: Set(tenant_id),
        secret_enc: Set(secret_enc),
        created_at: Set(now),
        confirmed_at: Set(confirmed.then_some(now)),
        last_used_step: Set(None),
    };
    let written = user_totp::Entity::insert(row)
        .on_conflict(
            OnConflict::column(user_totp::Column::UserId)
                .update_columns([
                    user_totp::Column::SecretEnc,
                    user_totp::Column::CreatedAt,
                    user_totp::Column::ConfirmedAt,
                    user_totp::Column::LastUsedStep,
                ])
                .action_and_where(
                    Expr::col((user_totp::Entity, user_totp::Column::ConfirmedAt)).is_null(),
                )
                .to_owned(),
        )
        .exec_without_returning(conn)
        .await
        .context("storing TOTP secret")?;
    Ok(written == 1)
}

/// The user's confirmed TOTP enrollment, if any.
pub async fn confirmed(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<Option<user_totp::Model>> {
    user_totp::Entity::find_by_id(user_id)
        .filter(user_totp::Column::TenantId.eq(tenant_id))
        .filter(user_totp::Column::ConfirmedAt.is_not_null())
        .one(conn)
        .await
        .context("loading TOTP enrollment")
}

/// Verifies `code` and records its step so it can't be replayed. The
/// conditional update makes two concurrent submissions of one code succeed
/// at most once.
pub async fn verify_for_user(
    conn: &impl ConnectionTrait,
    master_key: &[u8; 32],
    row: &user_totp::Model,
    code: &str,
) -> anyhow::Result<bool> {
    let secret = open_secret(master_key, row)?;
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
    let Some(step) = verify_code(&secret, code, now, row.last_used_step) else {
        return Ok(false);
    };
    let result = user_totp::Entity::update_many()
        .col_expr(user_totp::Column::LastUsedStep, Expr::value(step))
        .filter(user_totp::Column::UserId.eq(row.user_id))
        .filter(
            Condition::any()
                .add(user_totp::Column::LastUsedStep.is_null())
                .add(user_totp::Column::LastUsedStep.lt(step)),
        )
        .exec(conn)
        .await
        .context("recording TOTP step")?;
    Ok(result.rows_affected == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_sha1_vectors_truncated_to_six_digits() {
        // RFC 6238 Appendix B (8-digit values; we use the last 6).
        for (time, expected) in [
            (59u64, 287_082u32),
            (1_111_111_109, 81_804),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
        ] {
            assert_eq!(hotp(RFC_SECRET, time / STEP_SECS), expected, "t={time}");
        }
    }

    #[test]
    fn accepts_one_step_of_skew_and_rejects_replay() {
        let now = 1_111_111_109;
        let step = i64::try_from(now / STEP_SECS).unwrap();
        let code = |s: i64| format!("{:06}", hotp(RFC_SECRET, u64::try_from(s).unwrap()));
        assert_eq!(verify_code(RFC_SECRET, &code(step), now, None), Some(step));
        assert_eq!(
            verify_code(RFC_SECRET, &code(step - 1), now, None),
            Some(step - 1)
        );
        assert_eq!(
            verify_code(RFC_SECRET, &code(step + 1), now, None),
            Some(step + 1)
        );
        assert_eq!(verify_code(RFC_SECRET, &code(step - 2), now, None), None);
        // Replay: the step was already used.
        assert_eq!(verify_code(RFC_SECRET, &code(step), now, Some(step)), None);
        assert_eq!(
            verify_code(RFC_SECRET, &code(step), now, Some(step - 1)),
            Some(step)
        );
    }

    #[test]
    fn rejects_malformed_codes() {
        for bad in ["", "12345", "1234567", "12a456", "+12345"] {
            assert_eq!(verify_code(RFC_SECRET, bad, 59, None), None, "{bad}");
        }
    }

    #[test]
    fn sealed_secret_is_bound_to_user() {
        let master = [9u8; 32];
        let (tenant, user) = (Uuid::now_v7(), Uuid::now_v7());
        let sealed = seal_secret(&master, tenant, user, RFC_SECRET).unwrap();
        let now = chrono::Utc::now().fixed_offset();
        let mut row = user_totp::Model {
            user_id: user,
            tenant_id: tenant,
            secret_enc: sealed,
            created_at: now,
            confirmed_at: Some(now),
            last_used_step: None,
        };
        assert_eq!(open_secret(&master, &row).unwrap().as_slice(), RFC_SECRET);
        row.user_id = Uuid::now_v7();
        assert!(open_secret(&master, &row).is_err());
    }
}
