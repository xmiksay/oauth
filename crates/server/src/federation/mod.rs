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
pub mod github;
pub mod group_map;
pub mod id_token;
pub mod identities;
pub mod idps;
pub mod kinds;
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
const USER_AGENT: &str = concat!("oauth/", env!("CARGO_PKG_VERSION"));

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
        self.get_json_as(url, what, None, "application/json").await
    }

    /// [`Self::get_json`] with an optional bearer token and `Accept` value
    /// (APIs that aren't OpenID, e.g. GitHub's, want their own).
    async fn get_json_as<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        what: &'static str,
        bearer: Option<&str>,
        accept: &str,
    ) -> Result<T, Failure> {
        self.get_json_unless(url, what, bearer, accept, &[])
            .await?
            .ok_or(Failure(what))
    }

    /// [`Self::get_json_as`], but a response with one of the `absent`
    /// statuses is `Ok(None)` (the resource isn't granted) instead of a
    /// failure; every other error stays one.
    async fn get_json_unless<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        what: &'static str,
        bearer: Option<&str>,
        accept: &str,
        absent: &[reqwest::StatusCode],
    ) -> Result<Option<T>, Failure> {
        let parsed = urls::checked(url, self.allow_http_loopback).ok_or(Failure(what))?;
        let mut request = self
            .http
            .get(parsed)
            .header(reqwest::header::ACCEPT, accept)
            // GitHub's API refuses requests without one.
            .header(reqwest::header::USER_AGENT, USER_AGENT);
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(|err| {
            tracing::warn!(what, timeout = err.is_timeout(), "upstream unreachable");
            Failure(what)
        })?;
        if absent.contains(&response.status()) {
            return Ok(None);
        }
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
        serde_json::from_slice(&body)
            .map(Some)
            .map_err(|_| Failure(what))
    }
}
