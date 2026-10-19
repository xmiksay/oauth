//! Which upstream URLs we are willing to call, and the URLs we derive.

use std::net::IpAddr;

use entity::identity_providers;
use url::{Host, Url};

use super::resolve;
use crate::config::Config;

/// `https://` with a host, no credentials and no fragment; plain `http://`
/// only to a loopback host and only when `allow_http_loopback` (local
/// development and tests). Without that flag an IP literal must be public
/// (host names are checked when resolved, `resolve::PublicOnly`).
pub fn allowed(url: &Url, allow_http_loopback: bool) -> bool {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return false;
    }
    let Some(host) = url.host() else {
        return false;
    };
    let literal = match &host {
        Host::Ipv4(ip) => Some(IpAddr::V4(*ip)),
        Host::Ipv6(ip) => Some(IpAddr::V6(*ip)),
        Host::Domain(_) => None,
    };
    if !allow_http_loopback && literal.is_some_and(|ip| !resolve::is_public(ip)) {
        return false;
    }
    match url.scheme() {
        "https" => true,
        "http" => allow_http_loopback && is_loopback(&host),
        _ => false,
    }
}

fn is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(name) => {
            let name = name.to_ascii_lowercase();
            name == "localhost" || name.ends_with(".localhost")
        }
        Host::Ipv4(ip) => IpAddr::V4(*ip).is_loopback(),
        Host::Ipv6(ip) => IpAddr::V6(*ip).is_loopback(),
    }
}

/// `raw` parsed, if [`allowed`].
pub fn checked(raw: &str, allow_http_loopback: bool) -> Option<Url> {
    Url::parse(raw)
        .ok()
        .filter(|url| allowed(url, allow_http_loopback))
}

/// The configured discovery URL, else OIDC Discovery §4's default.
pub fn discovery_url(idp: &identity_providers::Model) -> String {
    match &idp.discovery_url {
        Some(url) => url.clone(),
        None => format!(
            "{}/.well-known/openid-configuration",
            idp.issuer.trim_end_matches('/')
        ),
    }
}

/// Our redirect URI at every upstream: the tenant's canonical host only.
pub fn callback_url(config: &Config, tenant_slug: &str) -> String {
    format!("{}/federation/callback", config.tenant_origin(tenant_slug))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(raw: &str, loopback: bool) -> bool {
        checked(raw, loopback).is_some()
    }

    #[test]
    fn https_only_unless_loopback_is_allowed() {
        assert!(ok("https://idp.example/x", false));
        assert!(!ok("http://idp.example/x", false));
        assert!(!ok("http://idp.example/x", true));
        assert!(!ok("http://127.0.0.1:8080/x", false));
        for loopback in [
            "http://127.0.0.1:8080/x",
            "http://127.3.2.1/x",
            "http://[::1]:9/x",
            "http://localhost:5173/x",
            "http://b.localhost:5173/x",
        ] {
            assert!(ok(loopback, true), "{loopback}");
        }
        assert!(!ok("http://10.0.0.1/x", true));
        assert!(!ok("http://localhost.example/x", true));
    }

    #[test]
    fn odd_urls_are_refused() {
        assert!(!ok("https://user:pw@idp.example/", false));
        assert!(!ok("https://10.0.0.1/", false));
        assert!(!ok("https://[::1]/", false));
        assert!(!ok("https://169.254.169.254/", false));
        assert!(ok("https://8.8.8.8/", false));
        assert!(ok("https://10.0.0.1/", true));
        assert!(!ok("https://idp.example/#frag", false));
        assert!(!ok("ftp://idp.example/", false));
        assert!(!ok("file:///etc/passwd", true));
        assert!(!ok("not a url", true));
    }
}
