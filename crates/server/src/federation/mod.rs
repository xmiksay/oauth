//! Upstream OpenID Connect federation (relying-party side): per-tenant
//! identity providers, discovery and JWKS caches, the code exchange, ID
//! token verification, the single-use round-trip state, linked identities
//! and the first-sign-in policy. The login flow lives in
//! `authn::federation`; docs in `docs/federation.md`.
//!
//! Every upstream failure is a [`Failure`] carrying a fixed reason code:
//! it goes to the audit log, the user only ever sees `upstream_failed`.

pub mod discovery;
pub mod exchange;
pub mod flow;
pub mod id_token;
pub mod identities;
pub mod idps;
pub mod policy;
pub mod profile;
pub mod resolve;
pub mod state;
pub mod urls;

use std::time::Duration;

use crate::http;

/// Why an upstream round trip failed (fixed codes, audit only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("upstream identity provider failed: {0}")]
pub struct Failure(pub &'static str);

/// Bounds every call to an identity provider; a sign-in waits on it.
const TIMEOUTS: http::Timeouts = http::Timeouts {
    total: Duration::from_secs(10),
    connect: Duration::from_secs(5),
};
/// Discovery documents, JWKS and token responses are small; anything bigger
/// is refused instead of buffered.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// The outbound side shared by all requests: one HTTP client plus the
/// discovery / JWKS caches (per process; replicas each keep their own).
pub struct Upstream {
    http: reqwest::Client,
    allow_http_loopback: bool,
    discovery: discovery::Cache,
}

impl Upstream {
    pub fn new(allow_http_loopback: bool) -> anyhow::Result<Self> {
        Ok(Self {
            // Development and tests talk to loopback providers; production
            // only to public addresses.
            http: http::client(
                TIMEOUTS,
                !allow_http_loopback,
                (!allow_http_loopback).then(|| {
                    std::sync::Arc::new(resolve::PublicOnly)
                        as std::sync::Arc<dyn reqwest::dns::Resolve>
                }),
            )?,
            allow_http_loopback,
            discovery: discovery::Cache::default(),
        })
    }

    pub fn allow_http_loopback(&self) -> bool {
        self.allow_http_loopback
    }

    /// GET `url` (which must pass the URL policy) and parse a JSON body.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        what: &'static str,
    ) -> Result<T, Failure> {
        let parsed = urls::checked(url, self.allow_http_loopback).ok_or(Failure(what))?;
        let response = self
            .http
            .get(parsed)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|err| {
                tracing::warn!(what, timeout = err.is_timeout(), "upstream unreachable");
                Failure(what)
            })?;
        if !response.status().is_success() {
            tracing::warn!(
                what,
                status = response.status().as_u16(),
                "upstream refused"
            );
            return Err(Failure(what));
        }
        let body = http::read_capped(response, MAX_RESPONSE_BYTES)
            .await
            .map_err(|_| Failure(what))?;
        serde_json::from_slice(&body).map_err(|_| Failure(what))
    }
}
