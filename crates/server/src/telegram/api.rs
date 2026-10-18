//! Minimal Telegram Bot API client (`sendMessage`, `setWebhook`).
//!
//! The bot token is part of every request URL (`/bot{token}/{method}`), so
//! neither URLs nor reqwest errors (which embed the URL) are ever logged or
//! returned: failures collapse into [`SendError`], which carries only a kind.

use std::{fmt, sync::Arc, time::Duration};

use anyhow::Context;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{config::TelegramConfig, mail::MailError};

/// Bounds one Bot API call; a login waits on `sendMessage`.
const TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Telegram's limit for one message.
pub const MAX_TEXT_CHARS: usize = 4096;

/// Why a call failed — the same transient / permanent split as mail, so
/// the outbox treats both channels alike.
pub type SendError = MailError;

#[derive(Clone)]
pub struct BotApi {
    http: reqwest::Client,
    /// `{api_url}/bot{token}` — secret.
    base: Arc<str>,
}

// Hand-written: `base` holds the token.
impl fmt::Debug for BotApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BotApi").finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Reply {
    ok: bool,
}

impl BotApi {
    pub fn new(config: &TelegramConfig) -> anyhow::Result<Self> {
        // An explicit AWS-LC provider: rustls is also built with ring (sqlx),
        // so there is no unambiguous process default to fall back on.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions for the Telegram client")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .timeout(TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            // An env proxy would see the token in every URL.
            .no_proxy()
            .https_only(config.api_url.starts_with("https://"))
            .build()
            .map_err(|e| anyhow::anyhow!("building the Telegram client: {}", e.without_url()))?;
        Ok(Self {
            http,
            base: format!("{}/bot{}", config.api_url, config.bot_token).into(),
        })
    }

    /// Calls `method`; `Ok` only when Telegram answered `ok: true`.
    async fn call(&self, method: &str, body: &Value) -> Result<(), SendError> {
        let response = self
            .http
            .post(format!("{}/{method}", self.base))
            .json(body)
            .send()
            .await
            .map_err(|err| {
                // Only the kind: the error's text would carry the URL.
                tracing::warn!(
                    method,
                    timeout = err.is_timeout(),
                    connect = err.is_connect(),
                    "Telegram API unreachable"
                );
                SendError::Transient
            })?;
        let status = response.status();
        let ok = response
            .json::<Reply>()
            .await
            .map(|r| r.ok)
            .unwrap_or(false);
        if status.is_success() && ok {
            return Ok(());
        }
        tracing::warn!(method, status = status.as_u16(), "Telegram API refused");
        Err(classify(status.as_u16()))
    }

    /// Sends `text` to `chat_id` (plain text, no link previews).
    pub async fn send_message(&self, chat_id: i64, text: &str) -> Result<(), SendError> {
        self.call("sendMessage", &send_message_body(chat_id, text))
            .await
    }

    /// Registers `url` as the bot's webhook with `secret` as its secret token.
    pub async fn set_webhook(&self, url: &str, secret: &str) -> Result<(), SendError> {
        let body = json!({
            "url": url,
            "secret_token": secret,
            "allowed_updates": ["message"],
        });
        self.call("setWebhook", &body).await
    }
}

/// `sendMessage` parameters (also used for replies in a webhook response).
pub fn send_message_body(chat_id: i64, text: &str) -> Value {
    let text: String = text.chars().take(MAX_TEXT_CHARS).collect();
    json!({
        "chat_id": chat_id,
        "text": text,
        "link_preview_options": { "is_disabled": true },
    })
}

/// 429 and 5xx are worth retrying; any other refusal (blocked bot, unknown
/// chat, bad token) won't change by itself.
fn classify(status: u16) -> SendError {
    if status == 429 || status >= 500 {
        SendError::Transient
    } else {
        SendError::Permanent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_classified() {
        assert_eq!(classify(429), SendError::Transient);
        assert_eq!(classify(502), SendError::Transient);
        for status in [200, 400, 401, 403, 404] {
            assert_eq!(classify(status), SendError::Permanent, "{status}");
        }
    }

    #[test]
    fn long_texts_are_cut_and_debug_hides_the_token() {
        let body = send_message_body(7, &"é".repeat(MAX_TEXT_CHARS + 10));
        assert_eq!(
            body["text"].as_str().unwrap().chars().count(),
            MAX_TEXT_CHARS
        );
        assert_eq!(body["chat_id"], 7);
        let cfg = TelegramConfig::parse(
            Some("1:tok-secret".into()),
            Some("oauth_bot".into()),
            Some("s".into()),
            None,
        )
        .unwrap()
        .unwrap();
        let api = BotApi::new(&cfg).unwrap();
        assert!(!format!("{api:?}").contains("tok-secret"));
    }
}
