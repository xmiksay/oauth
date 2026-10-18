//! Telegram bot: a linked chat receives sign-in codes (an MFA method) and
//! security notices. Optional (`TELEGRAM_*`); unset hides every feature.
//!
//! - `links`: My Account issues a single-use code (deep link
//!   `t.me/{bot}?start={code}`); the user's `/start {code}` in a private
//!   chat binds that chat (`webhook`). `/stop` unlinks every user of a chat.
//! - `otp`: 6-digit sign-in codes for a login transaction, sent inline.
//! - notices: `notify::event` queues `channel = telegram` outbox rows
//!   (recipient = user id); the outbox job delivers them through
//!   [`api::BotApi`], looking the chat up at send time.
//!
//! Chat ids and message texts are never logged.

pub mod api;
pub mod links;
pub mod otp;
pub mod update;
pub mod webhook;

use anyhow::Context;
use entity::{enums::Channel, outbox, tenants};
use sea_orm::DatabaseConnection;
use uuid::Uuid;

pub use api::BotApi;

use crate::{
    config::Config,
    jobs::outbox::{Courier, open_body},
    mail::MailError,
};

impl Courier for BotApi {
    const CHANNEL: Channel = Channel::Telegram;

    /// No (longer a) link for the recipient → permanent: the row is dead,
    /// never retried.
    async fn deliver(
        &self,
        db: &DatabaseConnection,
        config: &Config,
        row: &outbox::Model,
        _tenants: &[tenants::Model],
    ) -> Result<(), MailError> {
        let user_id = Uuid::parse_str(&row.recipient).map_err(|_| MailError::Permanent)?;
        let link = links::find(db, row.tenant_id, user_id)
            .await
            .map_err(|err| {
                tracing::warn!(message_id = %row.id, error = ?err, "loading Telegram link failed");
                MailError::Transient
            })?
            .ok_or(MailError::Permanent)?;
        let body = open_body(config, row)?;
        let text = format!("{}\n\n{}", row.subject, body.as_str());
        self.send_message(link.chat_id, &text).await
    }
}

/// The webhook URL: on the apex origin, which no tenant owns.
pub fn webhook_url(config: &Config) -> String {
    format!("{}{}", config.public_url.origin(), webhook::PATH)
}

/// `oauth telegram set-webhook`: registers [`webhook_url`] with the
/// configured secret token.
pub async fn set_webhook(config: &Config) -> anyhow::Result<String> {
    let telegram = config
        .telegram
        .as_ref()
        .context("Telegram is not configured (TELEGRAM_BOT_TOKEN, …)")?;
    let url = webhook_url(config);
    BotApi::new(telegram)?
        .set_webhook(&url, &telegram.webhook_secret)
        .await
        .map_err(|err| anyhow::anyhow!("setWebhook failed ({})", err.kind()))?;
    Ok(url)
}
