//! Runtime configuration, read once from environment variables at startup
//! (parsing in `env.rs`, `PUBLIC_URL` and host matching in `public_url.rs`).

mod env;
mod public_url;
mod smtp;
mod telegram;

use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::bail;

pub use public_url::{HostKind, PublicUrl};
pub use smtp::SmtpConfig;
pub use telegram::TelegramConfig;

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
    /// Externally visible apex origin; tenant `t` lives at (and is the
    /// issuer) `{scheme}://t.{host}[:port]`.
    pub public_url: PublicUrl,
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
    /// Outgoing mail; `None` hides every email feature.
    pub smtp: Option<SmtpConfig>,
    /// Telegram bot; `None` hides every Telegram feature.
    pub telegram: Option<TelegramConfig>,
}

// Hand-written so secrets never reach logs through `{:?}`.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("public_url", &self.public_url.origin())
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
            .field("smtp", &self.smtp)
            .field("telegram", &self.telegram)
            .finish()
    }
}

impl Config {
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
        if !self.cookie_secure && self.public_url.is_https() {
            bail!("COOKIE_SECURE=false is only allowed with an http:// PUBLIC_URL");
        }
        Ok(())
    }

    /// Origin of a tenant: its OIDC issuer, the only `Origin` its login API
    /// accepts, and the base of its SPA URLs.
    pub fn tenant_origin(&self, tenant_slug: &str) -> String {
        self.public_url.tenant_origin(tenant_slug)
    }

    /// WebAuthn RP ID of a tenant (its host, no port).
    pub fn tenant_rp_id(&self, tenant_slug: &str) -> String {
        self.public_url.tenant_rp_id(tenant_slug)
    }

    /// Whether email can be sent (verification, reset, invites, notices).
    pub fn email_enabled(&self) -> bool {
        self.smtp.is_some()
    }

    /// Whether the Telegram bot is configured (linking, codes, notices).
    pub fn telegram_enabled(&self) -> bool {
        self.telegram.is_some()
    }

    /// OIDC issuer of a tenant (= its origin, no path).
    pub fn issuer(&self, tenant_slug: &str) -> String {
        self.tenant_origin(tenant_slug)
    }
}
