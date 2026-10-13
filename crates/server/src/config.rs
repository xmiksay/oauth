//! Runtime configuration, read once from environment variables at startup.

use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};

const MASTER_KEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

impl FromStr for LogFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => bail!("expected `text` or `json`, got `{other}`"),
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    /// Externally visible base URL without trailing slash; issuer = `{public_url}/{tenant}`.
    pub public_url: String,
    /// AES-256-GCM key wrapping signing keys and TOTP secrets at rest.
    pub master_key: [u8; MASTER_KEY_LEN],
    pub listen_addr: SocketAddr,
    pub metrics_addr: SocketAddr,
    pub log_format: LogFormat,
    pub key_rotation_days: u32,
    pub key_prepublish_hours: u32,
    pub session_ttl_hours: u32,
    pub web_dist_dir: PathBuf,
    /// `false` only for plain-http local development: drops the cookies'
    /// `Secure` attribute and `__Host-` name prefix.
    pub cookie_secure: bool,
    /// Header carrying the client address set by a trusted reverse proxy
    /// (e.g. `X-Forwarded-For`); `None` = use the socket peer address.
    pub trusted_proxy_header: Option<String>,
}

// Hand-written so secrets never reach logs through `{:?}`.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("public_url", &self.public_url)
            .field("master_key", &"<redacted>")
            .field("listen_addr", &self.listen_addr)
            .field("metrics_addr", &self.metrics_addr)
            .field("log_format", &self.log_format)
            .field("key_rotation_days", &self.key_rotation_days)
            .field("key_prepublish_hours", &self.key_prepublish_hours)
            .field("session_ttl_hours", &self.session_ttl_hours)
            .field("web_dist_dir", &self.web_dist_dir)
            .field("cookie_secure", &self.cookie_secure)
            .field("trusted_proxy_header", &self.trusted_proxy_header)
            .finish()
    }
}

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
            public_url: parse_public_url(&required("PUBLIC_URL")?)?,
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
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.listen_addr == self.metrics_addr {
            bail!("LISTEN_ADDR and METRICS_ADDR must differ");
        }
        for (key, value) in [
            ("KEY_ROTATION_DAYS", self.key_rotation_days),
            ("KEY_PREPUBLISH_HOURS", self.key_prepublish_hours),
            ("SESSION_TTL_HOURS", self.session_ttl_hours),
        ] {
            if value == 0 {
                bail!("{key} must be greater than zero");
            }
        }
        // A next key must be published before the current one expires, or
        // relying parties with cached JWKS reject freshly signed tokens.
        if u64::from(self.key_prepublish_hours) >= u64::from(self.key_rotation_days) * 24 {
            bail!("KEY_PREPUBLISH_HOURS must be shorter than KEY_ROTATION_DAYS");
        }
        if !self.cookie_secure && self.public_url.starts_with("https://") {
            bail!("COOKIE_SECURE=false is only allowed with an http:// PUBLIC_URL");
        }
        Ok(())
    }

    /// `scheme://host[:port]` of [`Self::public_url`]: the only `Origin`
    /// accepted by the login JSON API.
    pub fn public_origin(&self) -> &str {
        let after_scheme = self.public_url.find("://").map_or(0, |i| i + 3);
        match self
            .public_url
            .get(after_scheme..)
            .and_then(|r| r.find('/'))
        {
            Some(slash) => self
                .public_url
                .get(..after_scheme + slash)
                .unwrap_or(&self.public_url),
            None => &self.public_url,
        }
    }

    /// Path part of [`Self::public_url`] (empty or `/prefix`), for cookie paths.
    pub fn public_path_prefix(&self) -> &str {
        self.public_url
            .get(self.public_origin().len()..)
            .unwrap_or("")
    }

    /// OIDC issuer of a tenant.
    pub fn issuer(&self, tenant_slug: &str) -> String {
        format!("{}/{tenant_slug}", self.public_url)
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

fn parse_public_url(raw: &str) -> anyhow::Result<String> {
    let url = raw.trim().trim_end_matches('/');
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .context("PUBLIC_URL must start with http:// or https://")?;
    if rest.is_empty() || rest.contains(['?', '#']) {
        bail!("PUBLIC_URL must be a base URL without query or fragment");
    }
    Ok(url.to_owned())
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
        assert_eq!(cfg.public_url, "https://id.example.com");
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
    }

    #[test]
    fn public_url_parts() {
        let mut env = base_env();
        let cfg = parse(&env).unwrap();
        assert_eq!(cfg.public_origin(), "https://id.example.com");
        assert_eq!(cfg.public_path_prefix(), "");
        assert_eq!(cfg.issuer("contoso"), "https://id.example.com/contoso");
        env.insert("PUBLIC_URL", "http://localhost:8080/idp/".into());
        env.insert("COOKIE_SECURE", "false".into());
        env.insert("TRUSTED_PROXY_HEADER", " X-Forwarded-For ".into());
        let cfg = parse(&env).unwrap();
        assert_eq!(cfg.public_origin(), "http://localhost:8080");
        assert_eq!(cfg.public_path_prefix(), "/idp");
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
        for bad in ["id.example.com", "ftp://x", "https://", "https://x/?a=b"] {
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
