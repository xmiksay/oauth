//! Fixed-window rate limiting in Postgres (shared by all replicas). Every
//! attempt counts — successes too — and is counted BEFORE verification, so
//! concurrent guesses can't slip past the limit.
//!
//! Trade-off: the per-account limit lets an attacker lock a victim out for
//! one window; the alternative (no per-account limit) lets a botnet spread
//! guesses over many IPs. Windows are short to bound the lockout.

use std::net::IpAddr;

use anyhow::Context;
use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use sea_orm::{ConnectionTrait, Statement};
use uuid::Uuid;

use crate::secret;

#[derive(Clone, Copy, Debug)]
pub struct Limit {
    pub max: i32,
    pub window_secs: i64,
}

/// Password / second-factor attempts from one IP within one tenant.
pub const PER_IP: Limit = Limit {
    max: 30,
    window_secs: 300,
};
/// Attempts against one account.
pub const PER_ACCOUNT: Limit = Limit {
    max: 10,
    window_secs: 900,
};
/// Login transactions started from one IP within one tenant (bounds the
/// rows an unauthenticated client can make `/authorize` create).
pub const AUTHORIZE_PER_IP: Limit = Limit {
    max: 60,
    window_secs: 300,
};

/// Home-realm discovery lookups from one IP within one tenant.
pub const DISCOVER_PER_IP: Limit = Limit {
    max: 30,
    window_secs: 300,
};

/// Upstream sign-ins started from one IP within one tenant.
pub const FEDERATION_PER_IP: Limit = Limit {
    max: 30,
    window_secs: 300,
};

/// Password-reset requests from one IP within one tenant.
pub const RESET_PER_IP: Limit = Limit {
    max: 10,
    window_secs: 900,
};
/// Password-reset requests naming one email address (known or not).
pub const RESET_PER_EMAIL: Limit = Limit {
    max: 3,
    window_secs: 900,
};
/// Email-link redemptions (verify, reset, invite) from one IP.
pub const LINK_PER_IP: Limit = Limit {
    max: 30,
    window_secs: 300,
};
/// Self-service mails (verification, email change) one account may request.
pub const MAIL_PER_ACCOUNT: Limit = Limit {
    max: 5,
    window_secs: 900,
};

/// Start of the window containing `now` (unix seconds).
pub fn window_start(now: i64, window_secs: i64) -> i64 {
    now.div_euclid(window_secs) * window_secs
}

/// Seconds until the window containing `now` ends (at least 1).
pub fn retry_after(now: i64, window_secs: i64) -> u64 {
    let remaining = window_start(now, window_secs) + window_secs - now;
    u64::try_from(remaining.max(1)).unwrap_or(1)
}

/// IPv6 clients get a whole /64 each (an end site's smallest allocation),
/// otherwise one host could rotate through 2^64 addresses.
pub fn ip_key(ip: Option<IpAddr>) -> String {
    match ip {
        None => "ip:unknown".to_owned(),
        Some(IpAddr::V4(v4)) => format!("ip:{v4}"),
        Some(IpAddr::V6(v6)) => {
            let prefix = u128::from(v6) & !((1u128 << 64) - 1);
            format!("ip:{}/64", std::net::Ipv6Addr::from(prefix))
        }
    }
}

/// The account bucket of a resolved user. Keyed by id, so every spelling
/// of the email that resolves to the user shares one bucket.
pub fn user_key(user_id: Uuid) -> String {
    format!("acct:{user_id}")
}

/// The account bucket of an email that resolved to no user: lower-cased by
/// Postgres `lower()` — the same function the user lookup and the unique
/// index use — so the two can never disagree on non-ASCII case folding.
/// Unknown and known accounts limit identically, so the bucket kind reveals
/// nothing about whether an account exists. The email must not contain
/// control characters (the password step rejects those up front).
pub async fn email_key(conn: &impl ConnectionTrait, email: &str) -> anyhow::Result<String> {
    Ok(format!("acct-email:{}", lowered_email(conn, email).await?))
}

/// An email as the user lookup normalises it (trim + Postgres `lower()`);
/// callers reject control characters before resolving the account at all.
pub async fn lowered_email(conn: &impl ConnectionTrait, email: &str) -> anyhow::Result<String> {
    let email = email.trim().to_owned();
    let row = conn
        .query_one_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            "SELECT lower($1) AS email",
            [email.into()],
        ))
        .await
        .context("normalizing email for rate limiting")?
        .context("lower() returned no row")?;
    row.try_get("", "email").context("reading lowered email")
}

/// Counts one attempt. `Err(retry_after_secs)` when over the limit.
pub async fn hit(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    key: &str,
    limit: Limit,
    now: DateTime<Utc>,
) -> anyhow::Result<Result<(), u64>> {
    let start_secs = window_start(now.timestamp(), limit.window_secs);
    let start: DateTime<FixedOffset> = Utc
        .timestamp_opt(start_secs, 0)
        .single()
        .context("rate limit window out of range")?
        .fixed_offset();
    let expires = start + chrono::Duration::seconds(limit.window_secs);
    let row = conn
        .query_one_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            r"INSERT INTO rate_limit_buckets (tenant_id, key_hash, window_start, count, expires_at)
              VALUES ($1, $2, $3, 1, $4)
              ON CONFLICT (tenant_id, key_hash, window_start)
              DO UPDATE SET count = rate_limit_buckets.count + 1
              RETURNING count",
            [
                tenant_id.into(),
                secret::hash(key).into(),
                start.into(),
                expires.into(),
            ],
        ))
        .await
        .context("counting rate limit attempt")?
        .context("rate limit upsert returned no row")?;
    let count: i32 = row
        .try_get("", "count")
        .context("reading rate limit count")?;
    if count > limit.max {
        Ok(Err(retry_after(now.timestamp(), limit.window_secs)))
    } else {
        Ok(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_math() {
        assert_eq!(window_start(0, 300), 0);
        assert_eq!(window_start(299, 300), 0);
        assert_eq!(window_start(300, 300), 300);
        assert_eq!(window_start(1_000_000_123, 900), 999_999_900);
        assert_eq!(retry_after(0, 300), 300);
        assert_eq!(retry_after(299, 300), 1);
        assert_eq!(retry_after(450, 300), 150);
    }

    #[test]
    fn keys() {
        assert_eq!(ip_key(None), "ip:unknown");
        assert_eq!(ip_key(Some("::1".parse().unwrap())), "ip:::/64");
        assert_eq!(
            ip_key(Some("2001:db8:1:2:aaaa::1".parse().unwrap())),
            "ip:2001:db8:1:2::/64"
        );
        assert_eq!(
            ip_key(Some("2001:db8:1:2:ffff::9".parse().unwrap())),
            ip_key(Some("2001:db8:1:2::1".parse().unwrap()))
        );
        assert_eq!(ip_key(Some("10.1.2.3".parse().unwrap())), "ip:10.1.2.3");
        assert_eq!(user_key(Uuid::nil()), format!("acct:{}", Uuid::nil()));
    }
}
