// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Outbox claim-then-send: leases, backoff bookkeeping, dropped bodies.
mod common;

use chrono::Duration;
use common::{flow::Fixture, mail::Capture};
use entity::{enums::Channel, enums::EmailTokenPurpose, outbox};
use oauth_server::{
    jobs::outbox::{LEASE, Report, claim},
    mail::{
        MailError, links,
        outbox::{NewMessage, enqueue},
        templates::Rendered,
    },
};
use sea_orm::EntityTrait;
use zeroize::Zeroizing;

async fn queue_invite(f: &Fixture) {
    links::send(
        &f.db,
        &f.config,
        &f.tenant,
        &f.user,
        EmailTokenPurpose::Invite,
        None,
    )
    .await
    .unwrap();
}

async fn row(f: &Fixture) -> outbox::Model {
    outbox::Entity::find().one(&f.db).await.unwrap().unwrap()
}

#[tokio::test]
async fn a_claim_leases_the_message_until_it_runs_out() {
    let f = Fixture::with_email().await;
    queue_invite(&f).await;
    let now = chrono::Utc::now().fixed_offset();
    // A run that claims and then dies before sending.
    let claimed = claim(&f.db, now, entity::enums::Channel::Email)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(row(&f).await.attempts, 1);
    // Inside the lease nobody picks it up again …
    let capture = Capture::default();
    assert_eq!(
        f.deliver_with(&capture, now + Duration::minutes(9)).await,
        Report::default()
    );
    // … after it, the next run delivers it, and the body is dropped.
    let report = f
        .deliver_with(&capture, now + LEASE + Duration::seconds(1))
        .await;
    assert_eq!(
        report,
        Report {
            sent: 1,
            ..Report::default()
        }
    );
    assert_eq!(capture.sent.lock().unwrap().len(), 1);
    let sent = row(&f).await;
    assert_eq!(sent.attempts, 2);
    assert!(sent.sent_at.is_some() && sent.body_enc.is_none());
}

#[tokio::test]
async fn failures_book_the_backoff_and_dead_messages_lose_their_body() {
    let f = Fixture::with_email().await;
    queue_invite(&f).await;
    let now = chrono::Utc::now().fixed_offset();
    let report = f
        .deliver_with(&Capture::failing(MailError::Transient), now)
        .await;
    assert_eq!(
        report,
        Report {
            retrying: 1,
            ..Report::default()
        }
    );
    let failed = row(&f).await;
    // (Postgres keeps microseconds.)
    let delay = failed.next_attempt_at - now;
    assert!(
        (delay - Duration::minutes(1)).num_milliseconds().abs() < 1,
        "{delay}"
    );
    assert_eq!(failed.last_error.as_deref(), Some("transient"));
    assert!(failed.body_enc.is_some(), "kept for the retry");
    let later = now + Duration::minutes(2);
    let report = f
        .deliver_with(&Capture::failing(MailError::Permanent), later)
        .await;
    assert_eq!(
        report,
        Report {
            dead: 1,
            ..Report::default()
        }
    );
    let dead = row(&f).await;
    assert!(dead.dead_at.is_some() && dead.body_enc.is_none());
}

#[tokio::test]
async fn unsendable_header_text_is_given_up_without_a_panic() {
    let f = Fixture::with_email().await;
    let rendered = Rendered {
        kind: "notice_test".into(),
        subject: "Hi\r\nBcc: victim@example.com".into(),
        body: Zeroizing::new("body".into()),
    };
    let msg = NewMessage {
        tenant_id: f.tenant.id,
        channel: Channel::Email,
        recipient: "ann@example.com",
        rendered: &rendered,
        ttl: Duration::hours(1),
    };
    enqueue(&f.db, &f.config.master_key, msg).await.unwrap();
    let capture = Capture::default();
    let report = f
        .deliver_with(&capture, chrono::Utc::now().fixed_offset())
        .await;
    assert_eq!(
        report,
        Report {
            dead: 1,
            ..Report::default()
        }
    );
    assert!(capture.sent.lock().unwrap().is_empty());
}
