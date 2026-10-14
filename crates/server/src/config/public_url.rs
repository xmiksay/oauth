//! `PUBLIC_URL`: the apex origin every tenant host hangs off
//! (`{slug}.{host}[:port]`), and the classification of request hosts
//! against it.

use std::fmt;

use anyhow::{Context, bail};

use crate::directory::slug;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicUrl {
    https: bool,
    /// Lower-case DNS name, no trailing dot.
    host: String,
    /// `None` = the scheme's default port (browsers omit it from `Host` and
    /// from `Origin`, so an explicit `:443` would never match).
    port: Option<u16>,
}

/// What a request's host is relative to [`PublicUrl`].
#[derive(Debug, PartialEq, Eq)]
pub enum HostKind {
    /// `PUBLIC_URL`'s own host.
    Apex,
    /// `{label}.{host}` with a slug-shaped label, lower-cased (the tenant
    /// may not exist).
    Tenant(String),
    /// Anything else, including other ports, IP literals and nested labels.
    Foreign,
}

impl PublicUrl {
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let url = raw.trim().trim_end_matches('/');
        let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            bail!("PUBLIC_URL must start with http:// or https://");
        };
        // Tenants live on subdomains and issuers are bare origins, so a path
        // prefix has no meaning (and would silently break every issuer).
        if rest.contains(['/', '?', '#', '@']) {
            bail!(
                "PUBLIC_URL must be an origin (scheme://host[:port]) without path, query or fragment"
            );
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) => {
                // Round-trip check: `0443` / `+443` parse, but aren't how a
                // browser writes the port it then sends.
                let parsed: u16 = port
                    .parse()
                    .ok()
                    .filter(|p: &u16| *p != 0 && p.to_string() == port)
                    .context("PUBLIC_URL has an invalid port")?;
                (host, Some(parsed))
            }
            None => (rest, None),
        };
        let host = host.to_ascii_lowercase();
        let labels_ok = host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
        // Room for the longest tenant label: `{63 chars}.` + host ≤ 253 (RFC 1035).
        if !labels_ok || host.len() > 253 - 64 {
            bail!("PUBLIC_URL must have a DNS host name (tenants are its subdomains)");
        }
        // WHATWG URL parsing reads a host ending in a numeric label (decimal,
        // or `0x` + hex) as IPv4 (`1.2.3`, `127.1`, `foo.0x1`), so browsers
        // would never send it as a DNS name.
        if host.rsplit('.').next().is_some_and(|l| {
            let hex = l
                .strip_prefix("0x")
                .map(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
            hex.unwrap_or_else(|| l.bytes().all(|b| b.is_ascii_digit()))
        }) {
            bail!("PUBLIC_URL must not be an IP address (tenants are its subdomains)");
        }
        let mut url = Self {
            https,
            host,
            port: None,
        };
        url.port = port.filter(|p| *p != url.default_port());
        Ok(url)
    }

    fn default_port(&self) -> u16 {
        if self.https { 443 } else { 80 }
    }

    pub fn is_https(&self) -> bool {
        self.https
    }

    fn scheme(&self) -> &'static str {
        if self.https { "https" } else { "http" }
    }

    fn port_suffix(&self) -> String {
        self.port.map(|p| format!(":{p}")).unwrap_or_default()
    }

    /// `scheme://host[:port]` of the apex.
    pub fn origin(&self) -> String {
        format!("{}://{}{}", self.scheme(), self.host, self.port_suffix())
    }

    /// `scheme://{slug}.host[:port]`: a tenant's origin (and OIDC issuer).
    pub fn tenant_origin(&self, slug: &str) -> String {
        format!(
            "{}://{slug}.{}{}",
            self.scheme(),
            self.host,
            self.port_suffix()
        )
    }

    /// `{slug}.host`: a tenant's WebAuthn RP ID (its host without the port;
    /// each tenant host is its own RP, so passkeys never cross tenants).
    pub fn tenant_rp_id(&self, slug: &str) -> String {
        format!("{slug}.{}", self.host)
    }

    /// The apex DNS name (lower case, no port).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Classifies a request authority (`Host` header value). Matching is
    /// exact apart from ASCII case (DNS names are case-insensitive) and a
    /// spelled-out default port (the same origin): a trailing dot or another
    /// port is a different origin to the browser, so it must not reach a
    /// tenant whose issuer it doesn't equal.
    pub fn host_kind(&self, authority: &str) -> HostKind {
        let (host, port) = match authority.rsplit_once(':') {
            // IPv6 literals (`[::1]:8080`) never match a DNS name.
            _ if authority.starts_with('[') => return HostKind::Foreign,
            Some((host, port)) => match port.parse::<u16>() {
                Ok(p) if p.to_string() == port => {
                    (host, Some(p).filter(|p| *p != self.default_port()))
                }
                _ => return HostKind::Foreign,
            },
            None => (authority, None),
        };
        if port != self.port || host.len() <= self.host.len() {
            return if port == self.port && host.eq_ignore_ascii_case(&self.host) {
                HostKind::Apex
            } else {
                HostKind::Foreign
            };
        }
        let split = host.len() - self.host.len();
        let (Some(label), Some(base)) = (
            host.get(..split).and_then(|l| l.strip_suffix('.')),
            host.get(split..),
        ) else {
            return HostKind::Foreign;
        };
        let label = label.to_ascii_lowercase();
        if !base.eq_ignore_ascii_case(&self.host) || slug::validate_format(&label).is_err() {
            return HostKind::Foreign;
        }
        HostKind::Tenant(label)
    }
}

impl fmt::Display for PublicUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.origin())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> PublicUrl {
        PublicUrl::parse(raw).unwrap()
    }

    #[test]
    fn origins() {
        let u = url("https://ID.Example.com/");
        assert_eq!(u.origin(), "https://id.example.com");
        assert_eq!(u.tenant_origin("acme"), "https://acme.id.example.com");
        let u = url("http://localhost:5173");
        assert_eq!(u.tenant_origin("acme"), "http://acme.localhost:5173");
        assert_eq!(u.tenant_rp_id("acme"), "acme.localhost");
        assert!(!u.is_https());
        // Default ports are dropped: browsers never send them.
        assert_eq!(url("https://x.test:443").origin(), "https://x.test");
        assert_eq!(url("http://x.test:80").origin(), "http://x.test");
        assert_eq!(url("http://x.test:443").origin(), "http://x.test:443");
        let longest = format!("{}tests", "a.".repeat(92));
        assert_eq!(longest.len(), 189);
        assert!(PublicUrl::parse(&format!("https://{longest}")).is_ok());
    }

    #[test]
    fn rejects_non_origins() {
        for bad in [
            "id.example.com",
            "ftp://x",
            "https://",
            "https://x/?a=b",
            "https://x#f",
            "https://x.test/idp",
            "https://x.test/idp/",
            "https://u@x.test",
            "https://x.test:0",
            "https://x.test:99999",
            "https://x.test:0443",
            "https://x.test:+443",
            "https://1.2.3",
            "https://id.127",
            "https://127.1",
            "https://foo.0x1",
            "https://foo.0x",
            "https://foo.0xbeef",
            "https://x.test:",
            "https://[::1]:8080",
            "https://127.0.0.1",
            "https://x..test",
            "https://-x.test",
            "https://x_y.test",
            // 190 chars: a 63-char tenant label would exceed 253.
            &format!("https://{}test", "a.".repeat(93)),
        ] {
            assert!(PublicUrl::parse(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn classifies_hosts() {
        let u = url("https://id.example.com");
        assert_eq!(u.host_kind("id.example.com"), HostKind::Apex);
        assert_eq!(u.host_kind("ID.Example.COM"), HostKind::Apex);
        let acme = HostKind::Tenant("acme".into());
        assert_eq!(u.host_kind("acme.id.example.com"), acme);
        assert_eq!(u.host_kind("ACME.ID.EXAMPLE.com"), acme);
        // A spelled-out default port is the same origin.
        assert_eq!(u.host_kind("acme.id.example.com:443"), acme);
        assert_eq!(u.host_kind("id.example.com:443"), HostKind::Apex);
        let plain = url("http://id.example.com");
        assert_eq!(plain.host_kind("acme.id.example.com:80"), acme);
        assert_eq!(
            plain.host_kind("acme.id.example.com:443"),
            HostKind::Foreign
        );
        for foreign in [
            "",
            "example.com",
            "evil.com",
            "acme.id.example.com.",
            "id.example.com.",
            "acme.id.example.com:80",
            "acme.id.example.com:8443",
            "acme.id.example.com:0443",
            "a.b.id.example.com",
            ".id.example.com",
            "acmeid.example.com",
            "-x.id.example.com",
            "a.id.example.com",
            "[::1]",
            "[::1]:443",
            "127.0.0.1",
            "acme.id.example.com.evil.com",
        ] {
            assert_eq!(u.host_kind(foreign), HostKind::Foreign, "{foreign}");
        }
    }

    #[test]
    fn classifies_hosts_with_port() {
        let u = url("http://localhost:5173");
        assert_eq!(u.host_kind("localhost:5173"), HostKind::Apex);
        assert_eq!(
            u.host_kind("acme.localhost:5173"),
            HostKind::Tenant("acme".into())
        );
        for foreign in [
            "localhost",
            "acme.localhost",
            "acme.localhost:8080",
            "acme.localhost:05173",
            "acme.localhost:+5173",
            "acme.localhost:5173:5173",
            "acme.localhost:80",
            "[::1]:5173",
        ] {
            assert_eq!(u.host_kind(foreign), HostKind::Foreign, "{foreign}");
        }
    }
}
