//! Outgoing mail settings (`SMTP_URL`, `SMTP_FROM`). Both optional: without
//! them every email feature (verification, reset, invites, notifications)
//! is hidden.
//!
//! Mail carries reset and invitation links, so the connection must be
//! encrypted and not downgradable: `smtps://` or `smtp://…?tls=required`.
//! Plain or opportunistic TLS is accepted only to a loopback host (a dev
//! sink like Mailpit), and never with credentials.

use std::fmt;

use anyhow::{Context, bail};
use lettre::{Address, AsyncSmtpTransport, Tokio1Executor};

#[derive(Clone)]
pub struct SmtpConfig {
    /// lettre connection URL, e.g. `smtps://user:pass@smtp.example.com` or
    /// `smtp://localhost:1025`; may embed credentials.
    pub url: String,
    /// Envelope / header From address; the display name is the tenant's.
    pub from: Address,
}

// Hand-written: the URL may carry SMTP credentials.
impl fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("url", &"<redacted>")
            .field("from", &self.from.to_string())
            .finish()
    }
}

impl SmtpConfig {
    /// `None` when neither variable is set; setting only one is an error.
    pub fn parse(url: Option<String>, from: Option<String>) -> anyhow::Result<Option<Self>> {
        match (url, from) {
            (None, None) => Ok(None),
            (Some(url), Some(from)) => {
                let url = url.trim().to_owned();
                require_tls(&url)?;
                // Parsed now so a typo fails startup, not the first send.
                // The error text is lettre's and never echoes the URL.
                AsyncSmtpTransport::<Tokio1Executor>::from_url(&url)
                    .map_err(|e| anyhow::anyhow!("SMTP_URL is not a valid SMTP URL: {e}"))?;
                let from = from
                    .trim()
                    .parse::<Address>()
                    .context("SMTP_FROM must be a bare email address (name@domain)")?;
                Ok(Some(Self { url, from }))
            }
            (Some(_), None) => bail!("SMTP_FROM is required when SMTP_URL is set"),
            (None, Some(_)) => bail!("SMTP_URL is required when SMTP_FROM is set"),
        }
    }
}

/// Rejects connections that could send mail (or credentials) in clear.
fn require_tls(raw: &str) -> anyhow::Result<()> {
    // Errors never echo the URL: it may carry a password.
    let url = url::Url::parse(raw).map_err(|_| anyhow::anyhow!("SMTP_URL is not a valid URL"))?;
    let tls = url
        .query_pairs()
        .find(|(k, _)| k == "tls")
        .map(|(_, v)| v.into_owned());
    let encrypted = match url.scheme() {
        "smtps" => true,
        "smtp" => tls.as_deref() == Some("required"),
        _ => bail!("SMTP_URL must use smtps:// or smtp://"),
    };
    if encrypted {
        return Ok(());
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("SMTP_URL sends credentials only over TLS: use smtps:// or ?tls=required");
    }
    let loopback = match url.host() {
        // `smtp` is no "special" scheme, so the URL parser leaves IP
        // literals as opaque host text.
        Some(url::Host::Domain(d)) => {
            d.eq_ignore_ascii_case("localhost")
                || d.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if !loopback {
        bail!(
            "SMTP_URL must use smtps:// or ?tls=required (plain SMTP only to a loopback dev sink)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_owned())
    }

    #[test]
    fn both_or_neither() {
        assert!(SmtpConfig::parse(None, None).unwrap().is_none());
        assert!(SmtpConfig::parse(s("smtp://localhost:1025"), None).is_err());
        assert!(SmtpConfig::parse(None, s("a@b.c")).is_err());
        let cfg = SmtpConfig::parse(s(" smtp://localhost:1025 "), s("noreply@id.example"))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.url, "smtp://localhost:1025");
        assert_eq!(cfg.from.to_string(), "noreply@id.example");
    }

    #[test]
    fn invalid_values_are_rejected() {
        for (url, from) in [
            ("ftp://x", "a@b.c"),
            ("not a url", "a@b.c"),
            ("smtp://localhost", "Name <a@b.c>"),
            ("smtp://localhost", "nobody"),
        ] {
            assert!(SmtpConfig::parse(s(url), s(from)).is_err(), "{url} {from}");
        }
        assert!(SmtpConfig::parse(s("smtps://u:p@mail.example:465"), s("a@b.c")).is_ok());
        assert!(SmtpConfig::parse(s("smtp://u:p@mail.example?tls=required"), s("a@b.c")).is_ok());
        assert!(SmtpConfig::parse(s("smtp://mail.example?tls=required"), s("a@b.c")).is_ok());
    }

    #[test]
    fn mail_never_travels_in_clear() {
        for bad in [
            "smtp://mail.example",
            "smtp://mail.example?tls=opportunistic",
            "smtp://user:pw@mail.example",
            "smtp://user:pw@mail.example?tls=opportunistic",
            "smtp://user:pw@localhost:1025",
            "smtp://10.0.0.5:25",
        ] {
            let err = SmtpConfig::parse(s(bad), s("a@b.c"))
                .unwrap_err()
                .to_string();
            assert!(!err.contains("pw"), "{err}");
        }
        for ok in [
            "smtp://localhost:1025",
            "smtp://127.0.0.1:1025",
            "smtp://[::1]:1025?tls=opportunistic",
            "smtps://mail.example",
            "smtp://mail.example?tls=required",
        ] {
            assert!(SmtpConfig::parse(s(ok), s("a@b.c")).is_ok(), "{ok}");
        }
    }

    #[test]
    fn debug_redacts_credentials() {
        let cfg = SmtpConfig::parse(s("smtps://user:hunter2@mail.example"), s("a@b.c"))
            .unwrap()
            .unwrap();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("hunter2") && dbg.contains("a@b.c"), "{dbg}");
    }
}
