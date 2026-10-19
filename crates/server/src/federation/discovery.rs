//! OIDC Discovery and JWKS of upstream providers, cached in memory.
//!
//! Discovery documents live 1 h. A JWKS lives 1 h too, and an ID token
//! signed with a key we don't know triggers a refetch (the provider
//! rotated) — at most once a minute per JWKS, so tokens with made-up `kid`s
//! can't turn us into a request amplifier.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use entity::identity_providers;
use jsonwebtoken::jwk::Jwk;
use serde::Deserialize;
use serde_json::Value;

use super::{Failure, Upstream, urls};

const METADATA_TTL: Duration = Duration::from_secs(3600);
/// A provider that failed discovery isn't asked again for this long, so a
/// broken or hostile one can't make every sign-in attempt a fetch.
const FAILURE_TTL: Duration = Duration::from_secs(30);
const JWKS_TTL: Duration = Duration::from_secs(3600);
const JWKS_REFETCH_MIN: Duration = Duration::from_secs(60);
/// Entries per cache (one per configured provider in practice); past it the
/// cache starts over rather than growing.
const MAX_ENTRIES: usize = 512;
const MAX_KEYS: usize = 100;

/// The parts of a discovery document we use.
#[derive(Clone, Debug, Deserialize)]
pub struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// A discovery outcome as cached.
type Fetched = Result<Arc<Metadata>, Failure>;

struct Jwks {
    keys: Arc<Vec<Jwk>>,
    fetched: Instant,
}

#[derive(Default)]
pub struct Cache {
    /// Keyed by IdP id + discovery URL + issuer: per provider, and a
    /// changed configuration is a new entry.
    metadata: Mutex<HashMap<String, (Instant, Fetched)>>,
    jwks: Mutex<HashMap<String, Jwks>>,
}

fn insert_bounded<V>(map: &mut HashMap<String, V>, key: String, value: V) {
    if map.len() >= MAX_ENTRIES && !map.contains_key(&key) {
        map.clear();
    }
    map.insert(key, value);
}

/// What to do about a JWKS lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fetch {
    /// The cached set is fresh and has the key.
    Use,
    Refetch,
    /// Unknown key, but the set was fetched less than a minute ago.
    Refuse,
}

/// `cached` = when the set was fetched and whether it holds the key.
pub fn jwks_decision(cached: Option<(Instant, bool)>, now: Instant) -> Fetch {
    match cached {
        None => Fetch::Refetch,
        Some((fetched, _)) if now.saturating_duration_since(fetched) >= JWKS_TTL => Fetch::Refetch,
        Some((_, true)) => Fetch::Use,
        Some((fetched, false)) if now.saturating_duration_since(fetched) >= JWKS_REFETCH_MIN => {
            Fetch::Refetch
        }
        Some(_) => Fetch::Refuse,
    }
}

/// The key `kid` names; without a `kid` only a set of exactly one key.
fn select<'a>(keys: &'a [Jwk], kid: Option<&str>) -> Option<&'a Jwk> {
    match kid {
        Some(kid) => keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid)),
        None => match keys {
            [only] => Some(only),
            _ => None,
        },
    }
}

impl Upstream {
    /// The provider's discovery document; its `issuer` must equal the
    /// configured one exactly and its endpoints must pass the URL policy.
    pub async fn metadata(
        &self,
        idp: &identity_providers::Model,
    ) -> Result<Arc<Metadata>, Failure> {
        let url = urls::discovery_url(idp);
        let key = format!("{} {url} {}", idp.id, idp.issuer);
        let now = Instant::now();
        {
            let cache = self
                .discovery
                .metadata
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some((at, cached)) = cache.get(&key) {
                let ttl = if cached.is_ok() {
                    METADATA_TTL
                } else {
                    FAILURE_TTL
                };
                if now.saturating_duration_since(*at) < ttl {
                    return cached.clone();
                }
            }
        }
        let fetched = self.fetch_metadata(idp, &url).await.map(Arc::new);
        let mut cache = self
            .discovery
            .metadata
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        insert_bounded(&mut cache, key, (now, fetched.clone()));
        fetched
    }

    async fn fetch_metadata(
        &self,
        idp: &identity_providers::Model,
        url: &str,
    ) -> Result<Metadata, Failure> {
        let meta: Metadata = self.get_json(url, "discovery").await?;
        if meta.issuer != idp.issuer {
            return Err(Failure("discovery_issuer_mismatch"));
        }
        let loopback = self.allow_http_loopback;
        for endpoint in [
            &meta.authorization_endpoint,
            &meta.token_endpoint,
            &meta.jwks_uri,
        ] {
            if urls::checked(endpoint, loopback).is_none() {
                return Err(Failure("discovery_endpoint_refused"));
            }
        }
        Ok(meta)
    }

    /// Drops what this process cached for the IdP (discovery and its JWKS),
    /// after its issuer or client changed.
    pub fn forget(&self, idp_id: uuid::Uuid) {
        let prefix = format!("{idp_id} ");
        let mut jwks_uris = Vec::new();
        {
            let mut cache = self
                .discovery
                .metadata
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            cache.retain(|key, (_, cached)| {
                if !key.starts_with(&prefix) {
                    return true;
                }
                if let Ok(meta) = cached {
                    jwks_uris.push(meta.jwks_uri.clone());
                }
                false
            });
        }
        let mut jwks = self
            .discovery
            .jwks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for uri in jwks_uris {
            jwks.remove(&uri);
        }
    }

    /// The verification key for a token header's `kid`.
    pub async fn signing_key(&self, jwks_uri: &str, kid: Option<&str>) -> Result<Jwk, Failure> {
        let now = Instant::now();
        let decision = {
            let cache = self
                .discovery
                .jwks
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let cached = cache.get(jwks_uri);
            let found = cached.and_then(|c| select(&c.keys, kid));
            match jwks_decision(cached.map(|c| (c.fetched, found.is_some())), now) {
                Fetch::Use => return found.cloned().ok_or(Failure("unknown_kid")),
                other => other,
            }
        };
        if decision == Fetch::Refuse {
            return Err(Failure("unknown_kid"));
        }
        let keys = Arc::new(self.fetch_jwks(jwks_uri).await?);
        let found = select(&keys, kid).cloned();
        let mut cache = self
            .discovery
            .jwks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        insert_bounded(&mut cache, jwks_uri.to_owned(), Jwks { keys, fetched: now });
        found.ok_or(Failure("unknown_kid"))
    }

    /// Keys we can't parse (other key types, encryption keys) are skipped
    /// rather than failing the whole set.
    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<Vec<Jwk>, Failure> {
        #[derive(Deserialize)]
        struct Set {
            keys: Vec<Value>,
        }
        let set: Set = self.get_json(jwks_uri, "jwks").await?;
        Ok(set
            .keys
            .into_iter()
            .take(MAX_KEYS)
            .filter_map(|k| serde_json::from_value(k).ok())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_refetch_is_rate_limited() {
        let t0 = Instant::now();
        let at = |secs| t0 + Duration::from_secs(secs);
        assert_eq!(jwks_decision(None, t0), Fetch::Refetch);
        assert_eq!(jwks_decision(Some((t0, true)), at(10)), Fetch::Use);
        assert_eq!(jwks_decision(Some((t0, false)), at(10)), Fetch::Refuse);
        assert_eq!(jwks_decision(Some((t0, false)), at(60)), Fetch::Refetch);
        assert_eq!(jwks_decision(Some((t0, true)), at(3600)), Fetch::Refetch);
    }

    #[test]
    fn keys_are_selected_by_kid() {
        let jwk = |kid: Option<&str>| -> Jwk {
            let mut value = serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "x": "AAAA" });
            if let Some(kid) = kid {
                value["kid"] = kid.into();
            }
            serde_json::from_value(value).unwrap()
        };
        let one = [jwk(Some("a"))];
        let two = [jwk(Some("a")), jwk(Some("b"))];
        assert!(select(&two, Some("b")).is_some());
        assert!(select(&two, Some("c")).is_none());
        assert!(select(&two, None).is_none());
        assert!(select(&one, None).is_some());
        assert!(select(&[jwk(None)], Some("a")).is_none());
    }

    #[test]
    fn caches_stay_bounded() {
        let mut map = HashMap::new();
        for i in 0..MAX_ENTRIES * 2 {
            insert_bounded(&mut map, i.to_string(), i);
        }
        assert!(map.len() <= MAX_ENTRIES);
    }
}
