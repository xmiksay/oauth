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
/// Enrolment setup calls (new TOTP secret, passkey creation options) of
/// one user. Separate from [`PER_ACCOUNT`]: a forced enrolment must not
/// spend the attempts its password and code entries need.
pub const ENROLL_PER_USER: Limit = Limit {
    max: 20,
    window_secs: 900,
};
/// Login transactions started from one IP within one tenant (bounds the
/// rows an unauthenticated client can make `/authorize` create).
pub const AUTHORIZE_PER_IP: Limit = Limit {
    max: 60,
    window_secs: 300,
};

/// Device authorizations requested from one IP within one tenant (bounds
/// the rows an unauthenticated client can make `/oauth2/devicecode` create).
pub const DEVICE_AUTHORIZE_PER_IP: Limit = Limit {
    max: 30,
    window_secs: 300,
};
/// User codes entered from one IP within one tenant.
pub const USER_CODE_PER_IP: Limit = Limit {
    max: 10,
    window_secs: 300,
};
/// User codes that matched no pending request, per tenant from all
/// addresses together ([`USER_CODE_MISS_KEY`]). Per-IP buckets alone don't
/// bound guessing: an IPv6 /48 is 65,536 of them. With this cap a tenant
/// takes at most 900 wrong guesses in a code's 15 minutes; against 20^8
/// (~2^34.6) codes that is a hit chance of ~3.5e-8 per live code. The price:
/// a flood of wrong codes blocks code entry tenant-wide for the window.
pub const USER_CODE_MISSES: Limit = Limit {
    max: 300,
    window_secs: 300,
};
pub const USER_CODE_MISS_KEY: &str = "usercode-miss";

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

/// FAILED client authentications at the back-channel endpoints (token,
/// revoke, introspect, device authorization) per client_id and client IP
/// ([`client_auth_key`]). Failure-only: [`check`] gates every attempt,
/// [`count`] runs only on a failure, so a client with the right secret never
/// fills it. Keyed by IP too, so a guesser can't lock a confidential client
/// out everywhere — only from the guesser's own address (/64).
pub const CLIENT_AUTH_FAILURES: Limit = Limit {
    max: 10,
    window_secs: 300,
};

/// The clock windows are computed from (`AppState::rate_clock`). The wall
/// clock in production; tests pin it, so a burst of attempts can never
/// straddle a window boundary and see its count reset partway through.
#[derive(Clone, Copy, Debug, Default)]
pub struct Clock {
    pinned: Option<DateTime<Utc>>,
}

impl Clock {
    /// A clock that always reads `at`.
    pub fn pinned(at: DateTime<Utc>) -> Self {
        Self { pinned: Some(at) }
    }

    pub fn now(self) -> DateTime<Utc> {
        self.pinned.unwrap_or_else(Utc::now)
    }
}

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

/// The [`CLIENT_AUTH_FAILURES`] bucket of a claimed client_id from one
/// address. Built the same way whether or not the client exists, so the
/// limiter reveals nothing about that. The IP part comes first and is
/// self-delimiting, so no (ip, client_id) pair can collide with another.
pub fn client_auth_key(client_id: &str, ip: Option<IpAddr>) -> String {
    format!("client-auth:{}:{client_id}", ip_key(ip))
}

/// The account bucket of a resolved user. Keyed by id, so every spelling
/// of the email that resolves to the user shares one bucket.
pub fn user_key(user_id: Uuid) -> String {
    format!("acct:{user_id}")
}

/// The enrolment-setup bucket of a user ([`ENROLL_PER_USER`]).
pub fn enroll_key(user_id: Uuid) -> String {
    format!("enroll:{user_id}")
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
    let count = count(conn, tenant_id, key, limit, now).await?;
    if count > limit.max {
        Ok(Err(retry_after(now.timestamp(), limit.window_secs)))
    } else {
        Ok(Ok(()))
    }
}

/// Counts one attempt and returns the window's count including it. The
/// upsert is atomic, so exactly one caller sees each value.
pub async fn count(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    key: &str,
    limit: Limit,
    now: DateTime<Utc>,
) -> anyhow::Result<i32> {
    let start = window_start_at(now, limit)?;
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
    row.try_get("", "count").context("reading rate limit count")
}

/// Whether the bucket is already full, without counting an attempt — for a
/// bucket that [`hit`] fills only on failures. `Err(retry_after_secs)` when
/// full. Concurrent attempts can each pass this before any of them is
/// counted; the per-IP bucket hit first bounds that overshoot.
pub async fn check(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    key: &str,
    limit: Limit,
    now: DateTime<Utc>,
) -> anyhow::Result<Result<(), u64>> {
    let start = window_start_at(now, limit)?;
    let row = conn
        .query_one_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            r"SELECT count FROM rate_limit_buckets
              WHERE tenant_id = $1 AND key_hash = $2 AND window_start = $3",
            [tenant_id.into(), secret::hash(key).into(), start.into()],
        ))
        .await
        .context("reading rate limit bucket")?;
    let count: i32 = match row {
        Some(row) => row
            .try_get("", "count")
            .context("reading rate limit count")?,
        None => 0,
    };
    if count >= limit.max {
        Ok(Err(retry_after(now.timestamp(), limit.window_secs)))
    } else {
        Ok(Ok(()))
    }
}

fn window_start_at(now: DateTime<Utc>, limit: Limit) -> anyhow::Result<DateTime<FixedOffset>> {
    let start_secs = window_start(now.timestamp(), limit.window_secs);
    Ok(Utc
        .timestamp_opt(start_secs, 0)
        .single()
        .context("rate limit window out of range")?
        .fixed_offset())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_clock_stands_still() {
        let at = Utc.timestamp_opt(1_000_000_299, 0).unwrap();
        let clock = Clock::pinned(at);
        assert_eq!(clock.now(), at);
        assert_eq!(clock.now(), at);
        let wall = Clock::default().now();
        assert!((Utc::now() - wall).num_seconds().abs() < 5);
    }

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
        assert_eq!(
            client_auth_key("web-app", Some("10.1.2.3".parse().unwrap())),
            "client-auth:ip:10.1.2.3:web-app"
        );
        assert_eq!(
            client_auth_key("web-app", Some("2001:db8:1:2::7".parse().unwrap())),
            "client-auth:ip:2001:db8:1:2::/64:web-app"
        );
        assert_ne!(
            client_auth_key("web-app", Some("10.1.2.3".parse().unwrap())),
            client_auth_key("web-app", Some("10.1.2.4".parse().unwrap()))
        );
        assert_eq!(client_auth_key("x", None), "client-auth:ip:unknown:x");
    }
}
