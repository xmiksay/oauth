// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The outbox job, security notices and notification preferences.
mod common;

use axum::http::{Method, StatusCode};
use chrono::Duration;
use common::{
    ORIGIN,
    flow::{Fixture, PASSWORD},
    mail::{Capture, only_to, token_in},
    mgmt::{call, mint_user_token},
};
use entity::{enums::EmailTokenPurpose, known_devices, outbox};
use oauth_server::{
    jobs::{outbox::Report, sweeper},
    mail::{MailError, links},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, QueryOrder, TransactionTrait};
use serde_json::json;

const ANN: &str = "ann@example.com";

async fn queue_reset(f: &Fixture) {
    let (status, _, _) = f
        .browser()
        .post_json(
            "/api/authn/password-reset",
            &json!({ "email": ANN }),
            ORIGIN,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    f.settle().await;
}

#[tokio::test]
async fn a_rolled_back_action_sends_nothing() {
    let f = Fixture::with_email().await;
    let txn = f.db.begin().await.unwrap();
    links::send(
        &txn,
        &f.config,
        &f.tenant,
        &f.user,
        EmailTokenPurpose::Reset,
        None,
    )
    .await
    .unwrap();
    txn.rollback().await.unwrap();
    assert_eq!(f.outbox_rows().await, 0);

    // An API call failing after its mail was queued: a duplicate address.
    let admin = common::mgmt::user_with_roles(
        &f.db,
        f.tenant.id,
        "admin@example.com",
        &[entity::enums::DirectoryRole::UserAdmin],
    )
    .await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &admin).await;
    let body = json!({ "email": "ANN@example.com", "display_name": "Dup", "invite": true });
    let (status, _) = call(
        &f.app,
        Method::POST,
        "/api/v1/users",
        Some(&token),
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(f.outbox_rows().await, 0);
    assert!(f.deliver().await.is_empty());
}

#[tokio::test]
async fn bodies_are_sealed_and_failures_retry_until_dead() {
    let f = Fixture::with_email().await;
    // An invitation: its 7-day lifetime outlasts every retry (a reset mail
    // would expire after 30 minutes and simply stop being attempted).
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
    let row = outbox::Entity::find().one(&f.db).await.unwrap().unwrap();
    let sealed = row.body_enc.clone().unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains("token="));
    assert_eq!((row.kind.as_str(), row.recipient.as_str()), ("invite", ANN));

    let failing = Capture::failing(MailError::Transient);
    let mut now = chrono::Utc::now().fixed_offset();
    for attempt in 1..=8 {
        let report = f.deliver_with(&failing, now).await;
        let expected = if attempt < 8 {
            Report {
                retrying: 1,
                ..Report::default()
            }
        } else {
            Report {
                dead: 1,
                ..Report::default()
            }
        };
        assert_eq!(report, expected, "attempt {attempt}");
        // Not due again before its backoff.
        assert_eq!(f.deliver_with(&failing, now).await, Report::default());
        now += Duration::hours(6);
    }
    let row = outbox::Entity::find().one(&f.db).await.unwrap().unwrap();
    assert_eq!(row.attempts, 8);
    assert!(row.dead_at.is_some() && row.sent_at.is_none());
    assert_eq!(row.last_error.as_deref(), Some("transient"));
    assert!(f.deliver().await.is_empty(), "dead messages are never sent");
}

#[tokio::test]
async fn permanent_failures_die_at_once_and_old_rows_are_swept() {
    let f = Fixture::with_email().await;
    f.verify(&f.user).await;
    queue_reset(&f).await;
    let now = chrono::Utc::now().fixed_offset();
    let report = f
        .deliver_with(&Capture::failing(MailError::Permanent), now)
        .await;
    assert_eq!(
        report,
        Report {
            dead: 1,
            ..Report::default()
        }
    );

    // Undelivered past its TTL (the link inside expired): never sent.
    queue_reset(&f).await;
    let late = now + Duration::minutes(31);
    assert_eq!(
        f.deliver_with(&Capture::default(), late).await,
        Report::default()
    );
    // The sweeper removes expired outbox rows and email tokens.
    sea_orm::ConnectionTrait::execute_unprepared(
        &f.db,
        "UPDATE outbox SET expires_at = now() - interval '1 second'; \
         UPDATE email_tokens SET expires_at = now() - interval '1 second'",
    )
    .await
    .unwrap();
    let report = sweeper::run_once(&f.db).await.unwrap().unwrap();
    let swept = |t: &str| report.iter().find(|(n, _)| *n == t).unwrap().1;
    assert_eq!((swept("outbox"), swept("email_tokens")), (2, 1));
    // (The second request had already voided the first reset token.)
}

#[tokio::test]
async fn new_browsers_trigger_a_sign_in_notice() {
    let f = Fixture::with_email().await;
    f.verify(&f.user).await;
    let url = common::browser::authorize_url("web-app", common::flow::WEB_CB, "openid", &[]);
    let again = common::browser::authorize_url(
        "web-app",
        common::flow::WEB_CB,
        "openid",
        &[("prompt", "login")],
    );
    // First sign-in ever: every browser is new, no notice — but recorded.
    let mut a = f.browser();
    a.login_for_code(&url, ANN).await;
    assert!(f.deliver().await.is_empty());
    assert!(a.cookies.contains_key("__Host-oauth_dev"));
    a.login_for_code(&again, ANN).await;
    assert!(f.deliver().await.is_empty(), "known browser");
    // Another browser: a notice.
    let mut b = f.browser();
    b.login_for_code(&url, ANN).await;
    let mails = f.deliver().await;
    assert!(only_to(&mails, ANN).subject.contains("New sign-in"));
    // An expired record counts as unknown.
    let newest = known_devices::Entity::find()
        .order_by_desc(known_devices::Column::Id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    let mut row: known_devices::ActiveModel = newest.into();
    row.expires_at = Set(chrono::Utc::now().fixed_offset() - Duration::seconds(1));
    row.update(&f.db).await.unwrap();
    b.login_for_code(&again, ANN).await;
    assert_eq!(f.deliver().await.len(), 1, "expired device record");

    // A second user of browser A: their first sign-in is quiet (another
    // user's devices don't count) …
    let bob = common::seed::add_user(&f.db, f.tenant.id, "bob@example.com", false).await;
    f.verify(&bob).await;
    a.login_for_code(&again, "bob@example.com").await;
    assert!(f.deliver().await.is_empty(), "bob's first sign-in");
    // … while a further browser of his gets a notice.
    let mut c = f.browser();
    c.login_for_code(&url, "bob@example.com").await;
    assert_eq!(
        only_to(&f.deliver().await, "bob@example.com").to,
        "bob@example.com"
    );
}

#[tokio::test]
async fn refresh_token_reuse_warns_the_user() {
    let f = Fixture::with_email().await;
    f.verify(&f.user).await;
    let (_b, tokens) = f.web_tokens("openid offline_access", ANN).await;
    f.deliver().await;
    let refresh = tokens["refresh_token"].as_str().unwrap();
    assert_eq!(f.refresh(refresh, None).await.0, StatusCode::OK);
    assert_eq!(f.refresh(refresh, None).await.0, StatusCode::BAD_REQUEST);
    let mails = f.deliver().await;
    let notice = only_to(&mails, ANN);
    assert!(notice.subject.contains("Suspicious activity"));
    assert!(
        notice.body.contains("Application: web-app app"),
        "{}",
        notice.body
    );
}

#[tokio::test]
async fn notification_preferences_are_respected() {
    let f = Fixture::with_email().await;
    let ann = f.verify(&f.user).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &ann).await;
    let tok = Some(token.as_str());
    let path = "/api/v1/me/notifications";
    let (status, prefs) = call(&f.app, Method::GET, path, tok, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        prefs["channels"],
        json!({ "email": true, "telegram": false })
    );
    assert_eq!(prefs["items"].as_array().unwrap().len(), 5);
    assert!(
        prefs["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["email"] == true)
    );

    let bad = json!({ "items": [{ "event": "nope", "email": false }] });
    assert_eq!(
        call(&f.app, Method::PUT, path, tok, Some(&bad)).await.0,
        StatusCode::BAD_REQUEST
    );
    // A repeated event is refused even when its first entry changes nothing.
    let twice = json!({ "items": [
        { "event": "mfa_changed", "email": true },
        { "event": "mfa_changed", "email": false },
    ] });
    assert_eq!(
        call(&f.app, Method::PUT, path, tok, Some(&twice)).await.0,
        StatusCode::BAD_REQUEST
    );
    let off = json!({ "items": [{ "event": "password_changed", "email": false }] });
    let (status, prefs) = call(&f.app, Method::PUT, path, tok, Some(&off)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        prefs["items"][0],
        json!({ "event": "password_changed", "email": false, "telegram": true })
    );

    let change = |from: &str, to: &str| json!({ "current_password": from, "new_password": to });
    let cp = "/api/v1/me/change-password";
    let (status, _) = call(
        &f.app,
        Method::POST,
        cp,
        tok,
        Some(&change(PASSWORD, "second passphrase")),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(f.deliver().await.is_empty(), "opted out");

    let on = json!({ "items": [{ "event": "password_changed", "email": true }] });
    call(&f.app, Method::PUT, path, tok, Some(&on)).await;
    let (status, _) = call(
        &f.app,
        Method::POST,
        cp,
        tok,
        Some(&change("second passphrase", "third passphrase")),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        only_to(&f.deliver().await, ANN)
            .subject
            .contains("password was changed")
    );
    assert_eq!(
        common::mgmt::audited(&f.db, "user.notification_prefs_update", ann.id)
            .await
            .len(),
        2
    );
}

#[tokio::test]
async fn unverified_addresses_get_no_notices_but_can_be_verified() {
    let f = Fixture::with_email().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let tok = Some(token.as_str());
    let body = json!({ "current_password": PASSWORD, "new_password": "second passphrase" });
    call(
        &f.app,
        Method::POST,
        "/api/v1/me/change-password",
        tok,
        Some(&body),
    )
    .await;
    assert!(f.deliver().await.is_empty());
    let (status, _) = call(&f.app, Method::POST, "/api/v1/me/verify-email", tok, None).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let link = token_in(only_to(&f.deliver().await, ANN), "/myaccount/verify-email");
    let (status, _, body) = f
        .browser()
        .post_json("/api/authn/email/verify", &json!({ "token": link }), ORIGIN)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
