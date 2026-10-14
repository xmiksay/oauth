//! [`Mailer`] over SMTP (lettre, rustls on AWS-LC).

use std::time::Duration;

use anyhow::anyhow;
use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::extension::ClientId,
};

use super::{Email, MailError, Mailer};
use crate::config::SmtpConfig;

/// Bounds each SMTP command; `jobs::outbox` bounds the whole send.
const TIMEOUT: Duration = Duration::from_secs(15);

pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Address,
}

impl SmtpMailer {
    /// `hello` = the EHLO name (our public host, not the container's).
    pub fn new(config: &SmtpConfig, hello: &str) -> anyhow::Result<Self> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(&config.url)
            .map_err(|e| anyhow!("SMTP_URL: {e}"))?
            .hello_name(ClientId::Domain(hello.to_owned()))
            .timeout(Some(TIMEOUT))
            .build();
        Ok(Self {
            transport,
            from: config.from.clone(),
        })
    }

    fn message(&self, email: &Email) -> Result<Message, MailError> {
        let to: Address = email.to.parse().map_err(|_| MailError::Permanent)?;
        Message::builder()
            .from(Mailbox::new(
                Some(email.from_name.clone()),
                self.from.clone(),
            ))
            .to(Mailbox::new(None, to))
            .subject(email.subject.clone())
            .header(ContentType::TEXT_PLAIN)
            .body(email.body.to_string())
            .map_err(|_| MailError::Permanent)
    }
}

impl Mailer for SmtpMailer {
    async fn send(&self, email: &Email) -> Result<(), MailError> {
        let message = self.message(email)?;
        self.transport.send(message).await.map(|_| ()).map_err(|e| {
            if e.is_permanent() {
                MailError::Permanent
            } else {
                MailError::Transient
            }
        })
    }
}
