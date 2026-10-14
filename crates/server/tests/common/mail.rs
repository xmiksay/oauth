//! Capturing mailer and helpers to pull links out of delivered mail.

use std::sync::{Arc, Mutex};

use entity::{outbox, users};
use oauth_server::{
    jobs::outbox::{Report, run_once},
    mail::{Email, MailError, Mailer},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, PaginatorTrait};
use tokio_util::sync::CancellationToken;

use super::{ORIGIN, flow::Fixture};

/// A delivered message as the test sees it.
#[derive(Clone, Debug)]
pub struct Sent {
    pub from_name: String,
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Records every message; with `fail` set, rejects them all instead.
#[derive(Clone, Default)]
pub struct Capture {
    pub sent: Arc<Mutex<Vec<Sent>>>,
    pub fail: Option<MailError>,
}

impl Mailer for Capture {
    async fn send(&self, email: &Email) -> Result<(), MailError> {
        if let Some(err) = self.fail {
            return Err(err);
        }
        self.sent.lock().unwrap().push(Sent {
            from_name: email.from_name.clone(),
            to: email.to.clone(),
            subject: email.subject.clone(),
            body: email.body.to_string(),
        });
        Ok(())
    }
}

impl Capture {
    pub fn failing(err: MailError) -> Self {
        Self {
            fail: Some(err),
            ..Self::default()
        }
    }
}

impl Fixture {
    /// Runs the outbox job once (now) and returns what it delivered.
    pub async fn deliver(&self) -> Vec<Sent> {
        let capture = Capture::default();
        // The clock is read after queued work has settled, so what it
        // queued is due.
        self.settle().await;
        self.deliver_with(&capture, chrono::Utc::now().fixed_offset())
            .await;
        capture.sent.lock().unwrap().clone()
    }

    /// Waits until work handlers left running (e.g. reset requests) is done.
    pub async fn settle(&self) {
        self.tasks.close();
        self.tasks.wait().await;
        self.tasks.reopen();
    }

    /// One outbox run with any mailer, on a fixed clock at `now`.
    pub async fn deliver_with<M: Mailer>(
        &self,
        mailer: &M,
        now: chrono::DateTime<chrono::FixedOffset>,
    ) -> Report {
        self.settle().await;
        let clock = move || now;
        run_once(
            &self.db,
            &self.config,
            mailer,
            &clock,
            &CancellationToken::new(),
        )
        .await
        .unwrap()
        .expect("outbox lock")
    }

    pub async fn outbox_rows(&self) -> u64 {
        outbox::Entity::find().count(&self.db).await.unwrap()
    }

    /// Marks `user`'s address verified (fixtures start unverified).
    pub async fn verify(&self, user: &users::Model) -> users::Model {
        let mut row: users::ActiveModel = user.clone().into();
        row.email_verified = Set(true);
        row.update(&self.db).await.unwrap()
    }
}

/// The single message sent to `to`, panicking otherwise.
pub fn only_to<'a>(mails: &'a [Sent], to: &str) -> &'a Sent {
    let found: Vec<&Sent> = mails.iter().filter(|m| m.to == to).collect();
    assert_eq!(found.len(), 1, "mails to {to}: {mails:#?}");
    found[0]
}

/// The token of the `{ORIGIN}{page}#token=…` link in `mail`'s body.
pub fn token_in(mail: &Sent, page: &str) -> String {
    let prefix = format!("{ORIGIN}{page}#token=");
    let start = mail
        .body
        .find(&prefix)
        .unwrap_or_else(|| panic!("no {prefix} link in {}", mail.body))
        + prefix.len();
    mail.body[start..]
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}
