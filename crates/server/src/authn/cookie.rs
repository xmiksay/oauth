//! The two cookies of the sign-in flow. Both use the `__Host-` prefix: the
//! browser then insists on `Secure`, `Path=/` and no `Domain`, so a sibling
//! subdomain can't plant ("toss") a cookie that shadows ours.
//!
//! - `__Host-oauth_sid_{tenant}`: the browser session of one tenant (the
//!   tenant is in the name because `__Host-` forbids a per-tenant `Path`).
//! - `__Host-oauth_tx`: binds login transactions to the browser that
//!   started them, shared by all tenants (transaction rows are
//!   tenant-scoped anyway). Each `/authorize` refreshes its `Max-Age`; it is
//!   never cleared explicitly, so parallel sign-ins in several tabs work.
//!
//! All `HttpOnly`, `SameSite=Lax` (sent on the relying party's top-level GET
//! to `/authorize`, not on cross-site POSTs). With `COOKIE_SECURE=false`
//! (plain-http dev) `Secure` and the prefix (which requires `Secure`) are
//! dropped; names and `Path=/` stay the same otherwise.

use anyhow::Context;
use axum::http::{HeaderMap, HeaderValue, header};

use super::tx::TX_TTL_MINUTES;
use crate::config::Config;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Session,
    TxBinding,
}

/// Cookie name; tenant slugs are `[a-z0-9-]`, valid in a cookie name.
pub fn name(config: &Config, kind: Kind, tenant_slug: &str) -> String {
    let prefix = if config.cookie_secure { "__Host-" } else { "" };
    match kind {
        Kind::Session => format!("{prefix}oauth_sid_{tenant_slug}"),
        Kind::TxBinding => format!("{prefix}oauth_tx"),
    }
}

fn build(
    config: &Config,
    kind: Kind,
    tenant_slug: &str,
    value: &str,
    max_age: i64,
) -> anyhow::Result<HeaderValue> {
    let secure = if config.cookie_secure { "; Secure" } else { "" };
    let raw = format!(
        "{}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}",
        name(config, kind, tenant_slug),
    );
    HeaderValue::from_str(&raw).context("building cookie")
}

pub fn set(
    config: &Config,
    kind: Kind,
    tenant_slug: &str,
    value: &str,
) -> anyhow::Result<HeaderValue> {
    let max_age = match kind {
        Kind::Session => i64::from(config.session_ttl_hours) * 3600,
        Kind::TxBinding => TX_TTL_MINUTES * 60,
    };
    build(config, kind, tenant_slug, value, max_age)
}

/// Same name and attributes as [`set`], so the browser replaces the cookie.
pub fn clear(config: &Config, kind: Kind, tenant_slug: &str) -> anyhow::Result<HeaderValue> {
    build(config, kind, tenant_slug, "", 0)
}

/// At most this many values of one cookie are considered: each costs a DB
/// lookup, and a client could otherwise repeat a name thousands of times.
pub const MAX_VALUES: usize = 4;

/// The values of the cookie (a browser may send several; capped).
pub fn read<'a>(
    headers: &'a HeaderMap,
    config: &Config,
    kind: Kind,
    tenant_slug: &str,
) -> impl Iterator<Item = &'a str> {
    let name = name(config, kind, tenant_slug);
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(move |pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name && !v.is_empty()).then_some(v)
        })
        .take(MAX_VALUES)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config(public_url: &str, secure: bool) -> Config {
        let env = HashMap::from([
            ("DATABASE_URL", "postgres://x".to_owned()),
            ("PUBLIC_URL", public_url.to_owned()),
            (
                "OAUTH_MASTER_KEY",
                "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=".to_owned(),
            ),
            ("COOKIE_SECURE", secure.to_string()),
        ]);
        Config::from_lookup(|k| env.get(k).cloned()).unwrap()
    }

    #[test]
    fn host_prefixed_cookies() {
        let c = config("https://id.example.com/idp", true);
        let v = set(&c, Kind::Session, "contoso", "tok").unwrap();
        assert_eq!(
            v.to_str().unwrap(),
            "__Host-oauth_sid_contoso=tok; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax; Secure"
        );
        let v = set(&c, Kind::TxBinding, "contoso", "b").unwrap();
        assert_eq!(
            v.to_str().unwrap(),
            "__Host-oauth_tx=b; Path=/; Max-Age=900; HttpOnly; SameSite=Lax; Secure"
        );
        let cleared = clear(&c, Kind::Session, "contoso").unwrap();
        assert_eq!(
            cleared.to_str().unwrap(),
            "__Host-oauth_sid_contoso=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure"
        );
    }

    #[test]
    fn dev_cookies_drop_secure_and_prefix() {
        let c = config("http://localhost:8080", false);
        let v = set(&c, Kind::Session, "contoso", "tok").unwrap();
        assert_eq!(
            v.to_str().unwrap(),
            "oauth_sid_contoso=tok; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax"
        );
        assert_eq!(name(&c, Kind::TxBinding, "contoso"), "oauth_tx");
    }

    #[test]
    fn reads_cookie_values_per_tenant() {
        let c = config("http://localhost", false);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; oauth_sid_contoso=x; oauth_sid_other=z; oauth_tx="),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("oauth_sid_contoso=y"),
        );
        let values: Vec<_> = read(&headers, &c, Kind::Session, "contoso").collect();
        assert_eq!(values, ["x", "y"]);
        assert_eq!(read(&headers, &c, Kind::TxBinding, "contoso").count(), 0);
    }

    #[test]
    fn repeated_values_are_capped() {
        let c = config("http://localhost", false);
        let line = vec!["oauth_tx=v"; 3000].join("; ");
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(&line).unwrap());
        assert_eq!(read(&headers, &c, Kind::TxBinding, "x").count(), MAX_VALUES);
    }
}
