// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Failed client authentication at the back-channel endpoints is limited
//! per client_id + client IP (issue #84).
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{browser::send, flow::Fixture};
use entity::audit_events;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use serde_json::Value;

const ATTACKER: &str = "203.0.113.7";
const OTHER: &str = "198.51.100.20";
const LIMIT: usize = 10;

async fn fixture() -> Fixture {
    Fixture::with_env(&[("TRUSTED_PROXY_HEADER", "x-forwarded-for")], false).await
}

/// POSTs a form from `ip` with Basic credentials.
async fn post(
    f: &Fixture,
    path: &str,
    ip: &str,
    client: (&str, &str),
    form: &[(&str, &str)],
) -> (StatusCode, Option<String>, Value) {
    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    let (id, secret) = client;
    let req = Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-forwarded-for", ip)
        .header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
        )
        .body(Body::from(body))
        .unwrap();
    let (status, headers, text) = send(&f.app, req).await;
    let retry_after = headers
        .get(header::RETRY_AFTER)
        .map(|v| v.to_str().unwrap().to_owned());
    (
        status,
        retry_after,
        serde_json::from_str(&text).unwrap_or(Value::Null),
    )
}

const CLIENT_CREDENTIALS: &[(&str, &str)] = &[
    ("grant_type", "client_credentials"),
    ("scope", "api://orders/.default"),
];

async fn token(f: &Fixture, ip: &str, client: (&str, &str)) -> (StatusCode, Option<String>, Value) {
    post(f, "/oauth2/token", ip, client, CLIENT_CREDENTIALS).await
}

fn assert_failed(resp: &(StatusCode, Option<String>, Value)) {
    assert_eq!(resp.0, StatusCode::UNAUTHORIZED, "{}", resp.2);
    assert_eq!(resp.2["error"], "invalid_client");
    assert_eq!(resp.1, None);
}

fn assert_limited(resp: &(StatusCode, Option<String>, Value)) {
    assert_eq!(resp.0, StatusCode::TOO_MANY_REQUESTS, "{}", resp.2);
    assert_eq!(resp.2["error"], "invalid_client");
    let secs: u64 = resp.1.as_deref().expect("Retry-After").parse().unwrap();
    assert!((1..=300).contains(&secs), "{secs}");
}

async fn lockouts(f: &Fixture) -> Vec<audit_events::Model> {
    audit_events::Entity::find()
        .filter(audit_events::Column::EventType.eq("client_auth.lockout"))
        .all(&f.db)
        .await
        .unwrap()
}

/// Starts a new window, as the next fixed window (or the sweeper) would.
async fn reset_buckets(f: &Fixture) {
    f.db.execute_unprepared("DELETE FROM rate_limit_buckets")
        .await
        .unwrap();
}

#[tokio::test]
async fn wrong_secrets_are_limited_per_client_and_ip() {
    let f = fixture().await;
    let right = ("web-app", f.web_secret.as_str());
    let wrong = ("web-app", "guess");
    for _ in 0..LIMIT {
        assert_failed(&token(&f, ATTACKER, wrong).await);
    }
    assert_limited(&token(&f, ATTACKER, wrong).await);
    // The right secret from the limited address is refused unverified too.
    assert_limited(&token(&f, ATTACKER, right).await);

    // The legitimate client elsewhere is unaffected, and so is another
    // client from the attacker's address.
    let (status, _, body) = token(&f, OTHER, right).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_failed(&token(&f, OTHER, wrong).await);
    let ledger = ("ledger", f.ledger_secret.as_str());
    let (status, _, body) = post(&f, "/oauth2/revoke", ATTACKER, ledger, &[("token", "x")]).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // One audit event for the lockout, not one per attempt.
    let events = lockouts(&f).await;
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.tenant_id, f.tenant.id);
    assert_eq!(event.actor_id, None);
    assert_eq!(event.target_type.as_deref(), Some("application"));
    assert_eq!(event.target_id, Some(f.web.id));
    assert_eq!(event.ip.as_deref(), Some(ATTACKER));
    assert_eq!(event.details, serde_json::json!({ "endpoint": "token" }));

    // A new window lets the right secret through again.
    reset_buckets(&f).await;
    let (status, _, body) = token(&f, ATTACKER, right).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn successes_do_not_fill_the_bucket() {
    let f = fixture().await;
    let right = ("web-app", f.web_secret.as_str());
    let wrong = ("web-app", "guess");
    for _ in 0..LIMIT - 1 {
        assert_failed(&token(&f, ATTACKER, wrong).await);
    }
    for _ in 0..LIMIT + 5 {
        let (status, _, body) = token(&f, ATTACKER, right).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert_failed(&token(&f, ATTACKER, wrong).await);
    assert_limited(&token(&f, ATTACKER, right).await);
}

#[tokio::test]
async fn unknown_clients_are_limited_the_same_way() {
    let f = fixture().await;
    let ghost = ("no-such-app", "guess");
    for _ in 0..LIMIT {
        assert_failed(&token(&f, ATTACKER, ghost).await);
    }
    let (status, retry, body) = token(&f, ATTACKER, ghost).await;
    assert_limited(&(status, retry, body.clone()));
    // Same body as a limited real client: nothing tells them apart.
    let wrong = ("web-app", "guess");
    for _ in 0..LIMIT {
        assert_failed(&token(&f, ATTACKER, wrong).await);
    }
    assert_eq!(token(&f, ATTACKER, wrong).await.2, body);

    let events = lockouts(&f).await;
    assert_eq!(events.len(), 2);
    let ghost_event = events.iter().find(|e| e.target_id.is_none()).unwrap();
    assert_eq!(ghost_event.target_type, None);
    assert_eq!(ghost_event.ip.as_deref(), Some(ATTACKER));
}

#[tokio::test]
async fn revoke_introspect_and_devicecode_share_the_bucket() {
    let f = fixture().await;
    let right = ("ledger", f.ledger_secret.as_str());
    let wrong = ("ledger", "guess");
    let tok = &[("token", "x")][..];
    for _ in 0..LIMIT / 2 {
        assert_failed(&post(&f, "/oauth2/revoke", ATTACKER, wrong, tok).await);
        assert_failed(&post(&f, "/oauth2/introspect", ATTACKER, wrong, tok).await);
    }
    for path in ["/oauth2/revoke", "/oauth2/introspect", "/oauth2/devicecode"] {
        assert_limited(&post(&f, path, ATTACKER, right, tok).await);
    }
    assert_limited(&token(&f, ATTACKER, right).await);
    let (status, _, body) = post(&f, "/oauth2/introspect", OTHER, right, tok).await;
    assert_eq!(
        (status, &body["active"]),
        (StatusCode::OK, &Value::Bool(false))
    );
    let events = lockouts(&f).await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].details,
        serde_json::json!({ "endpoint": "introspect" })
    );
}
