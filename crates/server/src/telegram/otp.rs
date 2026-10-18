//! Sign-in codes sent via Telegram at the MFA step: 6 random digits, one
//! live code per login transaction (a new send replaces it), 5 minutes,
//! 5 guesses, single use.

use anyhow::Context;
use chrono::Duration;
use sea_orm::{ConnectionTrait, Statement};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{authn::rate_limit::Limit, secret};

pub const OTP_TTL_MINUTES: i64 = 5;
pub const DIGITS: usize = 6;
/// Guesses at one code before it is dead.
pub const MAX_ATTEMPTS: i32 = 5;
/// Codes one user may be sent (counted per user, so new transactions don't
/// reset it).
pub const SEND_LIMIT: Limit = Limit {
    max: 3,
    window_secs: 900,
};

/// Uniform 6-digit code (rejection sampling in `secret::random_string`, so
/// no modulo bias).
pub fn generate() -> anyhow::Result<Zeroizing<String>> {
    secret::random_string(b"0123456789", DIGITS).map(Zeroizing::new)
}

/// Bound to the transaction, so equal codes of two logins differ at rest.
fn code_hash(tx_id: Uuid, code: &str) -> Vec<u8> {
    secret::hash(&format!("{tx_id}:{code}"))
}

/// What users type: digits, maybe with spaces.
fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace())
        .take(32)
        .collect()
}

/// Stores `code` as the transaction's live code (replacing an earlier one
/// and its attempt count).
pub async fn store(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    tx_id: Uuid,
    user_id: Uuid,
    code: &str,
) -> anyhow::Result<()> {
    let expires_at = chrono::Utc::now().fixed_offset() + Duration::minutes(OTP_TTL_MINUTES);
    conn.execute_raw(Statement::from_sql_and_values(
        conn.get_database_backend(),
        r"INSERT INTO telegram_otps (id, tenant_id, tx_id, user_id, code_hash, expires_at)
              VALUES ($1, $2, $3, $4, $5, $6)
              ON CONFLICT (tenant_id, tx_id) DO UPDATE SET
                  user_id = EXCLUDED.user_id, code_hash = EXCLUDED.code_hash, attempts = 0,
                  sent_at = now(), expires_at = EXCLUDED.expires_at",
        [
            Uuid::now_v7().into(),
            tenant_id.into(),
            tx_id.into(),
            user_id.into(),
            code_hash(tx_id, code).into(),
            expires_at.into(),
        ],
    ))
    .await
    .context("storing Telegram sign-in code")?;
    Ok(())
}

/// Checks `candidate` against the transaction's live code. Every call
/// spends one of the code's guesses BEFORE comparing (so concurrent
/// guesses can't exceed the limit); a match consumes the code.
pub async fn verify(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    tx_id: Uuid,
    user_id: Uuid,
    candidate: &str,
) -> anyhow::Result<bool> {
    let backend = conn.get_database_backend();
    let live = conn
        .query_one_raw(Statement::from_sql_and_values(
            backend,
            r"UPDATE telegram_otps SET attempts = attempts + 1
              WHERE tenant_id = $1 AND tx_id = $2 AND user_id = $3
                AND attempts < $4 AND expires_at > now()
              RETURNING id, code_hash",
            [
                tenant_id.into(),
                tx_id.into(),
                user_id.into(),
                MAX_ATTEMPTS.into(),
            ],
        ))
        .await
        .context("counting Telegram code attempt")?;
    let Some(live) = live else {
        return Ok(false);
    };
    let id: Uuid = live.try_get("", "id").context("reading code id")?;
    let stored: Vec<u8> = live.try_get("", "code_hash").context("reading code hash")?;
    let presented = code_hash(tx_id, &normalize(candidate));
    if !secret::ct_eq(&presented, &stored) {
        return Ok(false);
    }
    // Fenced on the hash: a code replaced (or used) in the meantime fails.
    let used = conn
        .execute_raw(Statement::from_sql_and_values(
            backend,
            "DELETE FROM telegram_otps WHERE id = $1 AND code_hash = $2",
            [id.into(), stored.into()],
        ))
        .await
        .context("consuming Telegram sign-in code")?;
    Ok(used.rows_affected() == 1)
}

/// The message carrying a code.
pub fn message(tenant_name: &str, code: &str) -> String {
    format!(
        "{code} is your {tenant_name} sign-in code. It expires in {OTP_TTL_MINUTES} minutes.\n\n\
         Never share it. If you aren't signing in right now, someone knows your password: \
         change it."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_six_uniform_digits() {
        let mut counts = [0u32; 10];
        for _ in 0..2000 {
            let code = generate().unwrap();
            assert_eq!(code.len(), DIGITS);
            for b in code.bytes() {
                assert!(b.is_ascii_digit());
                counts[usize::from(b - b'0')] += 1;
            }
        }
        // 12 000 digits, each expected 1 200 times (σ ≈ 33): a stuck or
        // skewed generator lands outside this band. (Freedom from modulo
        // bias comes from `secret::random_string`'s rejection sampling.)
        assert!(
            counts.iter().all(|&n| (1000..1400).contains(&n)),
            "{counts:?}"
        );
    }

    #[test]
    fn hashes_bind_the_transaction_and_input_is_normalized() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        assert_ne!(code_hash(a, "123456"), code_hash(b, "123456"));
        assert_eq!(
            code_hash(a, &normalize(" 123 456\n")),
            code_hash(a, "123456")
        );
        assert_eq!(normalize(&"9".repeat(100)).len(), 32);
    }

    #[test]
    fn message_names_tenant_and_code() {
        let text = message("Contoso", "042137");
        assert!(
            text.starts_with("042137 is your Contoso sign-in code"),
            "{text}"
        );
    }
}
