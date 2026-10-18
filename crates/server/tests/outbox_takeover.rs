// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Outbox runs never outlive or overwrite their lease: takeover by another
//! replica, the send deadline, and shutdown.
mod common;

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, FixedOffset, SubsecRound};
use common::{flow::Fixture, mail::Capture};
use entity::{enums::EmailTokenPurpose, outbox};
use oauth_server::{
    jobs::outbox::{LEASE, Report, claim, run_once},
    mail::{Email, MailError, Mailer, links},
};
use sea_orm::{DatabaseConnection, EntityTrait, QueryOrder};
use tokio_util::sync::CancellationToken;

type Clock = Arc<Mutex<DateTime<FixedOffset>>>;

/// Postgres keeps microseconds; so does this clock, for exact compares.
fn now_us() -> DateTime<FixedOffset> {
    chrono::Utc::now().fixed_offset().trunc_subsecs(6)
}

async fn queue_two(f: &Fixture) {
    for purpose in [EmailTokenPurpose::Invite, EmailTokenPurpose::Verify] {
        links::send(&f.db, &f.config, &f.tenant, &f.user, purpose, None)
            .await
            .unwrap();
    }
}

async fn rows(f: &Fixture) -> Vec<outbox::Model> {
    outbox::Entity::find()
        .order_by_asc(outbox::Column::Id)
        .all(&f.db)
        .await
        .unwrap()
}

/// During its first send, another replica claims the batch (its clock is
/// past our lease), as if our run had stalled.
struct Takeover {
    db: DatabaseConnection,
    at: DateTime<FixedOffset>,
    sent: Mutex<Vec<String>>,
    taken: Mutex<Option<usize>>,
    /// Also fired during that first send (shutdown racing the takeover).
    stop: Option<CancellationToken>,
}

impl Mailer for Takeover {
    async fn send(&self, email: &Email) -> Result<(), MailError> {
        let first = self.taken.lock().unwrap().is_none();
        if first {
            let claimed = claim(&self.db, self.at, entity::enums::Channel::Email)
                .await
                .unwrap()
                .unwrap()
                .len();
            *self.taken.lock().unwrap() = Some(claimed);
            if let Some(stop) = &self.stop {
                stop.cancel();
            }
        }
        self.sent.lock().unwrap().push(email.subject.clone());
        Ok(())
    }
}

/// Each send takes `step` of (simulated) time.
struct Slow {
    clock: Clock,
    step: Duration,
    sent: Mutex<u32>,
}

impl Mailer for Slow {
    async fn send(&self, _: &Email) -> Result<(), MailError> {
        let mut now = self.clock.lock().unwrap();
        *now += self.step;
        *self.sent.lock().unwrap() += 1;
        Ok(())
    }
}

#[tokio::test]
async fn a_run_that_lost_its_lease_sends_and_records_nothing_more() {
    let f = Fixture::with_email().await;
    queue_two(&f).await;
    f.settle().await;
    let now = now_us();
    let mailer = Takeover {
        db: f.db.clone(),
        at: now + LEASE + Duration::seconds(1),
        sent: Mutex::new(Vec::new()),
        taken: Mutex::new(None),
        stop: None,
    };
    let report = f.deliver_with(&mailer, now).await;
    assert_eq!(
        *mailer.taken.lock().unwrap(),
        Some(2),
        "the replica took both"
    );
    // The send in flight finished, but its outcome isn't ours to record;
    // the second message now belongs to the other replica: not sent.
    assert_eq!(mailer.sent.lock().unwrap().len(), 1);
    assert_eq!(report, Report::default());
    for row in rows(&f).await {
        assert_eq!(row.attempts, 2, "the newer claim stands");
        assert!(row.sent_at.is_none() && row.body_enc.is_some());
        assert_eq!(
            row.next_attempt_at,
            now + LEASE + Duration::seconds(1) + LEASE
        );
    }
}

#[tokio::test]
async fn no_send_starts_that_could_outlast_the_lease() {
    let f = Fixture::with_email().await;
    queue_two(&f).await;
    f.settle().await;
    let start = now_us();
    let clock: Clock = Arc::new(Mutex::new(start));
    // The first send takes 8m45s: a second (60 s budget + 30 s skew margin)
    // could end too close to the 10-minute lease's end.
    let step = Duration::minutes(8) + Duration::seconds(45);
    let mailer = Slow {
        clock: clock.clone(),
        step,
        sent: Mutex::new(0),
    };
    let read = move || *clock.lock().unwrap();
    let report = run_once(&f.db, &f.config, &mailer, &read, &CancellationToken::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        report,
        Report {
            sent: 1,
            ..Report::default()
        }
    );
    let rows = rows(&f).await;
    let (sent, rest): (Vec<_>, Vec<_>) = rows.iter().partition(|r| r.sent_at.is_some());
    // Sent at the real end of its send, not at claim time.
    assert_eq!(sent[0].sent_at, Some(start + step));
    // The untried one is handed back: due now, its claim not counted.
    assert_eq!(
        (rest[0].sent_at, rest[0].attempts, rest[0].next_attempt_at),
        (None, 0, start + step),
        "released"
    );
}

#[tokio::test]
async fn shutdown_releases_the_batch_before_any_send() {
    let f = Fixture::with_email().await;
    queue_two(&f).await;
    f.settle().await;
    let now = now_us();
    let capture = Capture::default();
    let stop = CancellationToken::new();
    stop.cancel();
    let clock = move || now;
    let report = run_once(&f.db, &f.config, &capture, &clock, &stop)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report, Report::default());
    assert!(capture.sent.lock().unwrap().is_empty());
    for row in rows(&f).await {
        // Released, not leased: a restarted replica sends it right away.
        assert_eq!((row.attempts, row.next_attempt_at), (0, now), "released");
        assert!(row.sent_at.is_none());
    }
}

#[tokio::test]
async fn releasing_on_shutdown_never_touches_a_taken_over_row() {
    let f = Fixture::with_email().await;
    queue_two(&f).await;
    f.settle().await;
    let now = now_us();
    let stop = CancellationToken::new();
    let later = now + LEASE + Duration::seconds(1);
    let mailer = Takeover {
        db: f.db.clone(),
        at: later,
        sent: Mutex::new(Vec::new()),
        taken: Mutex::new(None),
        stop: Some(stop.clone()),
    };
    let clock = move || now;
    run_once(&f.db, &f.config, &mailer, &clock, &stop)
        .await
        .unwrap()
        .unwrap();
    // The stale run stopped at the second row and "released" it — but it
    // is the other replica's now: its claim must stand.
    for row in rows(&f).await {
        assert_eq!((row.attempts, row.next_attempt_at), (2, later + LEASE));
    }
}
