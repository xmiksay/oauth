//! Outgoing email. Callers never send directly: they render a template and
//! [`outbox::enqueue`] it on their own transaction, so a message exists iff
//! the action that caused it committed; `jobs::outbox` delivers it through
//! a [`Mailer`] with retries. Bodies carry link tokens: they are sealed at
//! rest and never logged.

pub mod links;
pub mod outbox;
mod smtp;
pub mod templates;
pub mod tokens;

use std::{fmt, future::Future};

use zeroize::Zeroizing;

pub use smtp::SmtpMailer;

/// One message ready to hand to a [`Mailer`].
pub struct Email {
    /// Display name of the From header (the tenant's name); the address is
    /// the mailer's (`SMTP_FROM`).
    pub from_name: String,
    pub to: String,
    pub subject: String,
    pub body: Zeroizing<String>,
}

// Hand-written: the body carries link tokens.
impl fmt::Debug for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Email")
            .field("from_name", &self.from_name)
            .field("to", &self.to)
            .field("subject", &self.subject)
            .field("body", &"<redacted>")
            .finish()
    }
}

/// Why a delivery failed — only the kind, never server text (it may echo
/// the message).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailError {
    /// Worth retrying later (connection, timeout, 4xx).
    Transient,
    /// Retrying can't help (5xx rejection, unparsable address).
    Permanent,
}

impl MailError {
    /// Stored in `outbox.last_error` and logged.
    pub fn kind(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Permanent => "permanent",
        }
    }
}

pub trait Mailer: Send + Sync {
    fn send(&self, email: &Email) -> impl Future<Output = Result<(), MailError>> + Send;
}
