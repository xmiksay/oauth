//! Reading [`Config`] from environment variables.

use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};

use super::{Config, LogFormat, MASTER_KEY_LEN, PublicUrl, SmtpConfig, TelegramConfig};

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Parses config from an arbitrary key lookup so tests need not mutate the
    /// process environment.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let get = |key: &str| lookup(key).filter(|v| !v.trim().is_empty());
        let required = |key: &str| get(key).with_context(|| format!("{key} is required"));
        fn parsed<T: FromStr>(key: &str, raw: Option<String>, default: T) -> anyhow::Result<T>
        where
            T::Err: fmt::Display,
        {
            match raw {
                None => Ok(default),
                Some(v) => v
                    .trim()
                    .parse()
                    .map_err(|e| anyhow::anyhow!("{key}: invalid value `{v}`: {e}")),
            }
        }

        let config = Self {
            database_url: required("DATABASE_URL")?,
            public_url: PublicUrl::parse(&required("PUBLIC_URL")?)?,
            master_key: parse_master_key(&required("OAUTH_MASTER_KEY")?)?,
            listen_addr: parsed(
                "LISTEN_ADDR",
                get("LISTEN_ADDR"),
                SocketAddr::from(([0, 0, 0, 0], 8080)),
            )?,
            metrics_addr: parsed(
                "METRICS_ADDR",
                get("METRICS_ADDR"),
                SocketAddr::from(([0, 0, 0, 0], 9090)),
            )?,
            log_format: get("LOG_FORMAT")
                .map(|v| v.parse().context("LOG_FORMAT"))
                .transpose()?
                .unwrap_or(LogFormat::Text),
            key_rotation_days: parsed("KEY_ROTATION_DAYS", get("KEY_ROTATION_DAYS"), 90)?,
            key_prepublish_hours: parsed("KEY_PREPUBLISH_HOURS", get("KEY_PREPUBLISH_HOURS"), 48)?,
            session_ttl_hours: parsed("SESSION_TTL_HOURS", get("SESSION_TTL_HOURS"), 24)?,
            web_dist_dir: get("WEB_DIST_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("web/dist")),
            cookie_secure: parsed("COOKIE_SECURE", get("COOKIE_SECURE"), true)?,
            trusted_proxy_header: get("TRUSTED_PROXY_HEADER")
                .map(|h| parse_header_name(&h))
                .transpose()?,
            smtp: SmtpConfig::parse(get("SMTP_URL"), get("SMTP_FROM"))?,
            telegram: TelegramConfig::parse(
                get("TELEGRAM_BOT_TOKEN"),
                get("TELEGRAM_BOT_USERNAME"),
                get("TELEGRAM_WEBHOOK_SECRET"),
                get("TELEGRAM_API_URL"),
            )?,
        };
        config.validate()?;
        Ok(config)
    }
}

/// Lower-cased HTTP header name (token characters only).
fn parse_header_name(raw: &str) -> anyhow::Result<String> {
    let name = raw.trim().to_ascii_lowercase();
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid {
        bail!("TRUSTED_PROXY_HEADER: `{raw}` is not a valid header name");
    }
    Ok(name)
}

fn parse_master_key(raw: &str) -> anyhow::Result<[u8; MASTER_KEY_LEN]> {
    let bytes = STANDARD
        .decode(raw.trim())
        .context("OAUTH_MASTER_KEY must be standard base64")?;
    bytes.try_into().map_err(|b: Vec<u8>| {
        anyhow::anyhow!(
            "OAUTH_MASTER_KEY must decode to {MASTER_KEY_LEN} bytes, got {}",
            b.len()
        )
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn key_b64(len: usize) -> String {
        STANDARD.encode(vec![7u8; len])
    }

    fn base_env() -> HashMap<&'static str, String> {
        HashMap::from([
            ("DATABASE_URL", "postgres://u:p@localhost/oauth".to_owned()),
            ("PUBLIC_URL", "https://id.example.com/".to_owned()),
            ("OAUTH_MASTER_KEY", key_b64(32)),
        ])
    }

    fn parse(env: &HashMap<&'static str, String>) -> anyhow::Result<Config> {
        Config::from_lookup(|k| env.get(k).cloned())
    }

    #[test]
    fn minimal_env_uses_defaults() {
        let cfg = parse(&base_env()).unwrap();
        assert_eq!(cfg.public_url.origin(), "https://id.example.com");
        assert_eq!(cfg.master_key, [7u8; 32]);
        assert_eq!(cfg.listen_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(cfg.metrics_addr.to_string(), "0.0.0.0:9090");
        assert_eq!(cfg.log_format, LogFormat::Text);
        assert_eq!(cfg.key_rotation_days, 90);
        assert_eq!(cfg.key_prepublish_hours, 48);
        assert_eq!(cfg.session_ttl_hours, 24);
        assert_eq!(cfg.web_dist_dir, PathBuf::from("web/dist"));
        assert!(cfg.cookie_secure);
        assert_eq!(cfg.trusted_proxy_header, None);
        assert!(cfg.smtp.is_none() && !cfg.email_enabled());
        assert!(cfg.telegram.is_none() && !cfg.telegram_enabled());
    }

    #[test]
    fn telegram_settings() {
        let mut env = base_env();
        env.insert("TELEGRAM_BOT_TOKEN", "42:tok-secret".into());
        assert!(parse(&env).is_err(), "token without username and secret");
        env.insert("TELEGRAM_BOT_USERNAME", "oauth_bot".into());
        env.insert("TELEGRAM_WEBHOOK_SECRET", "hook-secret".into());
        let cfg = parse(&env).unwrap();
        assert!(cfg.telegram_enabled());
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("tok-secret") && !dbg.contains("hook-secret"),
            "{dbg}"
        );
        env.insert("TELEGRAM_API_URL", "http://10.0.0.1:8081".into());
        assert!(parse(&env).is_err(), "plain http off loopback");
    }

    #[test]
    fn smtp_settings() {
        let mut env = base_env();
        env.insert("SMTP_URL", "smtps://mailer:pw-secret@mail.example".into());
        assert!(parse(&env).is_err(), "SMTP_URL without SMTP_FROM");
        env.insert("SMTP_FROM", "noreply@id.example.com".into());
        let cfg = parse(&env).unwrap();
        assert!(cfg.email_enabled());
        assert!(!format!("{cfg:?}").contains("pw-secret"));
    }

    #[test]
    fn public_url_parts() {
        let mut env = base_env();
        let cfg = parse(&env).unwrap();
        assert_eq!(
            cfg.tenant_origin("contoso"),
            "https://contoso.id.example.com"
        );
        assert_eq!(cfg.issuer("contoso"), "https://contoso.id.example.com");
        env.insert("PUBLIC_URL", "http://localhost:8080/".into());
        env.insert("COOKIE_SECURE", "false".into());
        env.insert("TRUSTED_PROXY_HEADER", " X-Forwarded-For ".into());
        let cfg = parse(&env).unwrap();
        assert_eq!(cfg.issuer("contoso"), "http://contoso.localhost:8080");
        assert!(!cfg.cookie_secure);
        assert_eq!(cfg.trusted_proxy_header.as_deref(), Some("x-forwarded-for"));
    }

    #[test]
    fn insecure_cookies_need_plain_http() {
        let mut env = base_env();
        env.insert("COOKIE_SECURE", "false".into());
        assert!(parse(&env).is_err());
        env.insert("TRUSTED_PROXY_HEADER", "X Forwarded".into());
        env.insert("PUBLIC_URL", "http://localhost".into());
        assert!(parse(&env).is_err());
    }

    #[test]
    fn overrides_are_applied() {
        let mut env = base_env();
        env.insert("LISTEN_ADDR", "127.0.0.1:3000".into());
        env.insert("METRICS_ADDR", "127.0.0.1:3001".into());
        env.insert("LOG_FORMAT", "JSON".into());
        env.insert("KEY_ROTATION_DAYS", "30".into());
        env.insert("SESSION_TTL_HOURS", "8".into());
        env.insert("WEB_DIST_DIR", "/srv/web".into());
        let cfg = parse(&env).unwrap();
        assert_eq!(cfg.listen_addr.port(), 3000);
        assert_eq!(cfg.log_format, LogFormat::Json);
        assert_eq!(cfg.key_rotation_days, 30);
        assert_eq!(cfg.session_ttl_hours, 8);
        assert_eq!(cfg.web_dist_dir, PathBuf::from("/srv/web"));
    }

    #[test]
    fn missing_required_vars_are_reported() {
        for key in ["DATABASE_URL", "PUBLIC_URL", "OAUTH_MASTER_KEY"] {
            let mut env = base_env();
            env.remove(key);
            let err = parse(&env).unwrap_err().to_string();
            assert!(err.contains(key), "{key}: {err}");
            // Blank counts as missing.
            env.insert(key, "  ".into());
            assert!(parse(&env).is_err());
        }
    }

    #[test]
    fn master_key_must_be_32_bytes() {
        for len in [0, 16, 31, 33, 64] {
            let mut env = base_env();
            env.insert("OAUTH_MASTER_KEY", key_b64(len));
            assert!(parse(&env).is_err(), "len {len} accepted");
        }
    }

    #[test]
    fn master_key_must_be_base64() {
        let mut env = base_env();
        env.insert("OAUTH_MASTER_KEY", "not base64 at all!".into());
        let err = format!("{:#}", parse(&env).unwrap_err());
        assert!(err.contains("base64"), "{err}");
    }

    #[test]
    fn public_url_is_validated() {
        for bad in [
            "id.example.com",
            "ftp://x",
            "https://",
            "https://x/?a=b",
            // Tenants are subdomains; a path prefix is not supported.
            "https://id.example.com/idp",
        ] {
            let mut env = base_env();
            env.insert("PUBLIC_URL", bad.into());
            assert!(parse(&env).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn invalid_values_are_rejected() {
        let cases = [
            ("LOG_FORMAT", "yaml"),
            ("LISTEN_ADDR", "not-an-addr"),
            ("KEY_ROTATION_DAYS", "-1"),
            ("KEY_ROTATION_DAYS", "0"),
            ("SESSION_TTL_HOURS", "0"),
            ("KEY_PREPUBLISH_HOURS", "5000"),
            ("METRICS_ADDR", "0.0.0.0:8080"),
        ];
        for (key, value) in cases {
            let mut env = base_env();
            env.insert(key, value.into());
            assert!(parse(&env).is_err(), "{key}={value} accepted");
        }
    }

    #[test]
    fn debug_redacts_secrets() {
        let cfg = parse(&base_env()).unwrap();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("u:p@"));
        assert!(!dbg.contains(&key_b64(32)));
        assert!(!dbg.contains("[7, 7"));
    }
}
