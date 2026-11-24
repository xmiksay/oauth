//! Failure-only rate limit on client authentication at the back-channel
//! endpoints (`authn::rate_limit::CLIENT_AUTH_FAILURES`, keyed by tenant +
//! claimed client_id + client IP). [`guard`] runs before the client is even
//! looked up and refuses a full bucket WITHOUT verifying the secret, so
//! guesses past the limit learn nothing — not even whether the client
//! exists. [`failed`] counts a failure; the one that fills the bucket of an
//! existing client is audited once (`client_auth.lockout`). An unknown
//! client_id gets the same bucket and 429 but no audit row: an event naming
//! nothing helps nobody, and random client_ids would let one address fill
//! the tenant's audit log.
//!
//! Concurrent attempts can each pass [`guard`] before any of them is
//! counted, so a burst overshoots the limit by at most its in-flight
//! requests. Counting before verification would close that, but then every
//! successful call would write twice and a busy client (a resource server
//! introspecting in parallel) would be refused by its own successes.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use entity::enums::Outcome;
use sea_orm::ConnectionTrait;
use serde_json::json;
use uuid::Uuid;

use super::error::{OAuthError, OAuthResult};
use crate::{
    audit::{self, Actor, Event, EventType, Target},
    authn::rate_limit::{self, CLIENT_AUTH_FAILURES},
    metrics,
};

/// The endpoint authenticating the client (metric label, audit detail).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Token,
    Revoke,
    Introspect,
    DeviceAuthorization,
}

impl Endpoint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Revoke => "revoke",
            Self::Introspect => "introspect",
            Self::DeviceAuthorization => "devicecode",
        }
    }
}

/// Where an authentication attempt comes from and what it claims.
pub struct Attempt<'a> {
    pub tenant_id: Uuid,
    pub ip: Option<IpAddr>,
    pub endpoint: Endpoint,
    pub client_id: &'a str,
    /// Read from `AppState::rate_clock`.
    pub now: DateTime<Utc>,
}

impl Attempt<'_> {
    fn key(&self) -> String {
        rate_limit::client_auth_key(self.client_id, self.ip)
    }
}

/// 429 (`OAuthError::client_rate_limited`) when the bucket is full.
pub async fn guard(conn: &impl ConnectionTrait, attempt: &Attempt<'_>) -> OAuthResult<()> {
    let key = attempt.key();
    let checked = rate_limit::check(
        conn,
        attempt.tenant_id,
        &key,
        CLIENT_AUTH_FAILURES,
        attempt.now,
    )
    .await?;
    checked.map_err(|retry_after| {
        metrics::client_auth_limited(attempt.endpoint.as_str());
        OAuthError::client_rate_limited(retry_after)
    })
}

/// Counts a failed authentication; `app_id` is the claimed client's id when
/// it exists. The caller still answers this attempt with its own error.
pub async fn failed(
    conn: &impl ConnectionTrait,
    attempt: &Attempt<'_>,
    app_id: Option<Uuid>,
) -> OAuthResult<()> {
    let key = attempt.key();
    let count = rate_limit::count(
        conn,
        attempt.tenant_id,
        &key,
        CLIENT_AUTH_FAILURES,
        attempt.now,
    )
    .await?;
    if let Some(app_id) = app_id
        && fills_bucket(count)
    {
        audit::record(
            conn,
            Event {
                tenant_id: attempt.tenant_id,
                actor: Actor::User(None),
                event_type: EventType::ClientAuthLockout,
                target: Some(Target::Application(app_id)),
                outcome: Outcome::Failure,
                ip: attempt.ip,
                details: json!({ "endpoint": attempt.endpoint.as_str() }),
            },
        )
        .await?;
    }
    Ok(())
}

/// The upsert hands each count to exactly one caller, so exactly one
/// failure per window sees the bucket become full: one audit per lockout.
fn fills_bucket(count: i32) -> bool {
    count == CLIENT_AUTH_FAILURES.max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_filling_failure_is_a_lockout() {
        let max = CLIENT_AUTH_FAILURES.max;
        assert!(!fills_bucket(1));
        assert!(!fills_bucket(max - 1));
        assert!(fills_bucket(max));
        assert!(!fills_bucket(max + 1));
    }

    #[test]
    fn endpoint_labels_are_fixed() {
        let labels = [
            Endpoint::Token,
            Endpoint::Revoke,
            Endpoint::Introspect,
            Endpoint::DeviceAuthorization,
        ]
        .map(Endpoint::as_str);
        assert_eq!(labels, ["token", "revoke", "introspect", "devicecode"]);
    }

    #[test]
    fn attempts_from_other_addresses_use_other_buckets() {
        let attempt = |ip: &str| Attempt {
            tenant_id: Uuid::nil(),
            ip: Some(ip.parse().unwrap()),
            endpoint: Endpoint::Token,
            client_id: "web-app",
            now: Utc::now(),
        };
        assert_ne!(attempt("10.0.0.1").key(), attempt("10.0.0.2").key());
        assert_eq!(attempt("10.0.0.1").key(), attempt("10.0.0.1").key());
    }
}
