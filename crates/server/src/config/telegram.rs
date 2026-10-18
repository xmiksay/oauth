//! Telegram bot settings (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_USERNAME`,
//! `TELEGRAM_WEBHOOK_SECRET`, `TELEGRAM_API_URL`). All optional: without the
//! first three every Telegram feature (linking, sign-in codes, notices) is
//! hidden. The token and the webhook secret are credentials: never logged.

use std::fmt;

use anyhow::bail;

pub const DEFAULT_API_URL: &str = "https://api.telegram.org";

#[derive(Clone)]
pub struct TelegramConfig {
    /// `123456:ABC-…` from BotFather; part of every Bot API URL.
    pub bot_token: String,
    /// The bot's @username without `@` (deep links `https://t.me/{username}`).
    pub bot_username: String,
    /// Telegram echoes it in `X-Telegram-Bot-Api-Secret-Token` on every
    /// webhook call (registered by `oauth telegram set-webhook`).
    pub webhook_secret: String,
    /// Bot API origin, no trailing slash.
    pub api_url: String,
}

// Hand-written: token and webhook secret are credentials.
impl fmt::Debug for TelegramConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelegramConfig")
            .field("bot_token", &"<redacted>")
            .field("bot_username", &self.bot_username)
            .field("webhook_secret", &"<redacted>")
            .field("api_url", &self.api_url)
            .finish()
    }
}

impl TelegramConfig {
    /// `None` when token, username and secret are all unset; a partial set
    /// is an error. Errors never echo the token or the secret.
    pub fn parse(
        token: Option<String>,
        username: Option<String>,
        secret: Option<String>,
        api_url: Option<String>,
    ) -> anyhow::Result<Option<Self>> {
        let (token, username, secret) = match (token, username, secret) {
            (None, None, None) => {
                if api_url.is_some() {
                    bail!("TELEGRAM_API_URL is set but the Telegram bot is not configured");
                }
                return Ok(None);
            }
            (Some(t), Some(u), Some(s)) => (t, u, s),
            _ => bail!(
                "TELEGRAM_BOT_TOKEN, TELEGRAM_BOT_USERNAME and TELEGRAM_WEBHOOK_SECRET \
                 must be set together (or none of them)"
            ),
        };
        let bot_token = token.trim().to_owned();
        if !valid_token(&bot_token) {
            bail!("TELEGRAM_BOT_TOKEN must look like `<bot id>:<secret>` (from BotFather)");
        }
        let bot_username = username.trim().trim_start_matches('@').to_owned();
        if !valid_username(&bot_username) {
            bail!("TELEGRAM_BOT_USERNAME must be 5-32 characters of A-Z, a-z, 0-9 and _");
        }
        let webhook_secret = secret.trim().to_owned();
        if !valid_secret(&webhook_secret) {
            bail!("TELEGRAM_WEBHOOK_SECRET must be 1-256 characters of A-Z, a-z, 0-9, _ and -");
        }
        let api_url = parse_api_url(api_url.as_deref().unwrap_or(DEFAULT_API_URL))?;
        Ok(Some(Self {
            bot_token,
            bot_username,
            webhook_secret,
            api_url,
        }))
    }
}

/// `<digits>:<url-safe>`: it is a URL path segment, so nothing else may
/// appear in it.
fn valid_token(token: &str) -> bool {
    token.split_once(':').is_some_and(|(id, key)| {
        !id.is_empty()
            && id.len() <= 20
            && id.bytes().all(|b| b.is_ascii_digit())
            && (1..=128).contains(&key.len())
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

fn valid_username(name: &str) -> bool {
    (5..=32).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The Bot API's own rule for `secret_token` (setWebhook).
fn valid_secret(secret: &str) -> bool {
    (1..=256).contains(&secret.len())
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// An `https://` origin, or `http://` to a loopback host (a fake API in
/// tests / dev): the token travels in the URL.
fn parse_api_url(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let url = url::Url::parse(trimmed)
        .map_err(|_| anyhow::anyhow!("TELEGRAM_API_URL is not a valid URL"))?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        bail!("TELEGRAM_API_URL must be an origin (scheme://host[:port])");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("TELEGRAM_API_URL must not carry credentials");
    }
    let loopback = match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => bail!("TELEGRAM_API_URL must have a host"),
    };
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => bail!("TELEGRAM_API_URL must use https:// (http only to a loopback host)"),
        _ => bail!("TELEGRAM_API_URL must use https://"),
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "123456:AAH-secret_token";

    fn s(v: &str) -> Option<String> {
        Some(v.to_owned())
    }

    fn full(api: Option<&str>) -> anyhow::Result<Option<TelegramConfig>> {
        TelegramConfig::parse(
            s(TOKEN),
            s("@oauth_bot"),
            s("hook-secret_1"),
            api.map(Into::into),
        )
    }

    #[test]
    fn all_or_nothing() {
        assert!(
            TelegramConfig::parse(None, None, None, None)
                .unwrap()
                .is_none()
        );
        assert!(TelegramConfig::parse(s(TOKEN), None, None, None).is_err());
        assert!(TelegramConfig::parse(None, s("oauth_bot"), s("x"), None).is_err());
        assert!(TelegramConfig::parse(s(TOKEN), s("oauth_bot"), None, None).is_err());
        assert!(TelegramConfig::parse(None, None, None, s("https://api.telegram.org")).is_err());
        let cfg = full(None).unwrap().unwrap();
        assert_eq!(cfg.bot_username, "oauth_bot");
        assert_eq!(cfg.api_url, DEFAULT_API_URL);
        assert_eq!(cfg.webhook_secret, "hook-secret_1");
    }

    #[test]
    fn values_are_validated() {
        for bad in ["", "abc", "12:", ":abc", "12:ab/c", "12:ab c", "x1:abc"] {
            let parsed = TelegramConfig::parse(s(bad), s("oauth_bot"), s("x"), None);
            assert!(parsed.is_err(), "token {bad:?}");
        }
        for bad in ["bot", "has space", "dash-bot", &"b".repeat(33)] {
            let parsed = TelegramConfig::parse(s(TOKEN), s(bad), s("x"), None);
            assert!(parsed.is_err(), "username {bad:?}");
        }
        for bad in ["", "white space", "slash/", "dot.", &"a".repeat(257)] {
            let parsed = TelegramConfig::parse(s(TOKEN), s("oauth_bot"), s(bad), None);
            assert!(parsed.is_err(), "secret {bad:?}");
        }
        assert!(TelegramConfig::parse(s(TOKEN), s("oauth_bot"), s(&"a".repeat(256)), None).is_ok());
    }

    #[test]
    fn api_url_is_https_or_loopback() {
        for ok in [
            "https://api.telegram.org/",
            "http://127.0.0.1:8081",
            "http://localhost:9000",
            "http://[::1]:1",
        ] {
            assert!(full(Some(ok)).is_ok(), "{ok}");
        }
        assert_eq!(
            full(Some("http://127.0.0.1:8081/"))
                .unwrap()
                .unwrap()
                .api_url,
            "http://127.0.0.1:8081"
        );
        for bad in [
            "http://api.telegram.org",
            "ftp://127.0.0.1",
            "https://api.telegram.org/bot",
            "https://user:pw@api.telegram.org",
            "https://api.telegram.org?x=1",
            "not a url",
        ] {
            assert!(full(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn errors_and_debug_never_show_credentials() {
        let err = TelegramConfig::parse(s("123:has space"), s("oauth_bot"), s("x"), None)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("has space"), "{err}");
        let err = TelegramConfig::parse(s(TOKEN), s("oauth_bot"), s("bad secret!"), None)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("bad secret"), "{err}");
        let dbg = format!("{:?}", full(None).unwrap().unwrap());
        assert!(
            !dbg.contains("AAH-secret") && !dbg.contains("hook-secret"),
            "{dbg}"
        );
        assert!(dbg.contains("oauth_bot"), "{dbg}");
    }
}
