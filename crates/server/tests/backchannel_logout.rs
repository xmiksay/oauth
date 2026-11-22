// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Logout revokes the session's refresh tokens (tenant setting) and
//! OpenID Connect Back-Channel Logout 1.0: recipients, the logout token,
//! delivery through the outbox to a mock RP endpoint, and the settings.
mod common;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU16, Ordering},
};

use axum::{
    Router,
    extract::State,
    http::{Method, StatusCode},
    routing::post,
};
use common::{
    backchannel::{logout_url, queued, set_uri},
    flow::Fixture,
    get,
    mgmt::{call, mint_user_token, user_with_roles},
};
use entity::{enums::DirectoryRole, tenants};
use oauth_server::{
    backchannel::{deliver::Notifier, token},
    jobs::outbox::{Report, run_once},
    tokens::jwt,
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectionTrait};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

/// A relying party's back-channel logout endpoint on loopback http.
#[derive(Clone, Default)]
struct MockRp {
    received: Arc<Mutex<Vec<(String, String)>>>,
    status: Arc<AtomicU16>,
}

async fn receive(
    State(rp): State<MockRp>,
    headers: axum::http::HeaderMap,
    body: String,
) -> StatusCode {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    rp.received.lock().unwrap().push((content_type, body));
    StatusCode::from_u16(rp.status.load(Ordering::SeqCst)).unwrap()
}

impl MockRp {
    async fn start() -> (Self, String) {
        let rp = Self::default();
        rp.status.store(200, Ordering::SeqCst);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/bcl", post(receive))
            .with_state(rp.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (rp, format!("http://{addr}/bcl"))
    }

    /// The `logout_token`s received so far (checking the form encoding).
    fn tokens(&self) -> Vec<String> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .map(|(content_type, body)| {
                assert_eq!(content_type, "application/x-www-form-urlencoded");
                let (key, value) = form_urlencoded::parse(body.as_bytes()).next().unwrap();
                assert_eq!(key, "logout_token");
                value.into_owned()
            })
            .collect()
    }
}

async fn deliver(f: &Fixture) -> Report {
    let now = chrono::Utc::now().fixed_offset();
    let clock = move || now;
    let notifier = Notifier::new(true).unwrap();
    run_once(
        &f.db,
        &f.config,
        &notifier,
        &clock,
        &CancellationToken::new(),
    )
    .await
    .unwrap()
    .unwrap()
}

fn claim<'a>(claims: &'a serde_json::Map<String, Value>, name: &str) -> &'a str {
    claims[name].as_str().unwrap()
}

#[tokio::test]
async fn logout_notifies_the_rp_with_a_signed_logout_token() {
    let f = Fixture::new().await;
    let (rp, uri) = MockRp::start().await;
    set_uri(&f, Some(&uri)).await;
    let (mut browser, tokens) = f.web_tokens("openid", "ann@example.com").await;
    let id_token = tokens["id_token"].as_str().unwrap();
    let id_claims = f.verify_jwt(id_token, "web-app").await;

    let (status, _, _) = browser.get(&logout_url(id_token)).await;
    assert_eq!(status, StatusCode::FOUND);
    let rows = queued(&f).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].recipient, f.web.id.to_string());
    assert_eq!(rows[0].kind, "backchannel_logout");

    assert_eq!(
        deliver(&f).await,
        Report {
            sent: 1,
            ..Report::default()
        }
    );
    let received = rp.tokens();
    assert_eq!(received.len(), 1);
    let header = jsonwebtoken::decode_header(&received[0]).unwrap();
    assert_eq!(header.typ.as_deref(), Some(token::TYP));
    let issuer = f.config.issuer(&f.tenant.slug);
    let claims = jwt::verify(&f.db, f.tenant.id, &issuer, &received[0], token::TYP, true)
        .await
        .unwrap();
    assert_eq!(claim(&claims, "aud"), "web-app");
    assert_eq!(claim(&claims, "sid"), claim(&id_claims, "sid"));
    assert_eq!(claim(&claims, "sub"), claim(&id_claims, "sub"));
    assert_eq!(claims["events"], json!({ token::EVENT: {} }));
    assert!(claims.get("nonce").is_none());
    assert!(claims.get("jti").is_some());
    let lifetime = claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap();
    assert_eq!(lifetime, token::TTL_SECS);
    let sent = &queued(&f).await[0];
    assert!(sent.sent_at.is_some() && sent.body_enc.is_none());
}

#[tokio::test]
async fn only_clients_of_the_ended_session_with_a_uri_are_notified() {
    let f = Fixture::new().await;
    // No URI: nothing is queued.
    let (mut browser, tokens) = f.web_tokens("openid", "ann@example.com").await;
    let hint = tokens["id_token"].as_str().unwrap();
    browser.get(&logout_url(hint)).await;
    assert!(queued(&f).await.is_empty());

    let (_rp, uri) = MockRp::start().await;
    set_uri(&f, Some(&uri)).await;
    let (mut one, first) = f.web_tokens("openid", "ann@example.com").await;
    let (_two, _) = f.web_tokens("openid", "ann@example.com").await;
    // Only the session that ends, not the user's other one.
    one.get(&logout_url(first["id_token"].as_str().unwrap()))
        .await;
    assert_eq!(queued(&f).await.len(), 1);
}

#[tokio::test]
async fn rp_failures_are_retried_or_given_up() {
    let f = Fixture::new().await;
    let (rp, uri) = MockRp::start().await;
    set_uri(&f, Some(&uri)).await;
    for (status, expected) in [
        (
            503,
            Report {
                retrying: 1,
                ..Report::default()
            },
        ),
        (
            400,
            Report {
                dead: 1,
                ..Report::default()
            },
        ),
    ] {
        f.db.execute_unprepared("DELETE FROM outbox").await.unwrap();
        rp.status.store(status, Ordering::SeqCst);
        let (mut browser, tokens) = f.web_tokens("openid", "ann@example.com").await;
        browser
            .get(&logout_url(tokens["id_token"].as_str().unwrap()))
            .await;
        assert_eq!(deliver(&f).await, expected, "{status}");
    }
    // A URI removed before delivery: the row is dead, nothing sent.
    f.db.execute_unprepared("DELETE FROM outbox").await.unwrap();
    rp.status.store(200, Ordering::SeqCst);
    let (mut browser, tokens) = f.web_tokens("openid", "ann@example.com").await;
    browser
        .get(&logout_url(tokens["id_token"].as_str().unwrap()))
        .await;
    set_uri(&f, None).await;
    let before = rp.tokens().len();
    let report = deliver(&f).await;
    assert_eq!(report.dead, 1);
    assert_eq!(rp.tokens().len(), before);
}

#[tokio::test]
async fn logout_revokes_refresh_tokens_unless_the_tenant_opts_out() {
    let f = Fixture::new().await;
    let scope = "openid offline_access";
    let (mut browser, tokens) = f.web_tokens(scope, "ann@example.com").await;
    let refresh = tokens["refresh_token"].as_str().unwrap();
    browser
        .get(&logout_url(tokens["id_token"].as_str().unwrap()))
        .await;
    let (status, body) = f.refresh(refresh, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");

    let mut row: tenants::ActiveModel = f.tenant.clone().into();
    row.logout_revokes_refresh_tokens = Set(false);
    row.update(&f.db).await.unwrap();
    let (mut browser, tokens) = f.web_tokens(scope, "ann@example.com").await;
    browser
        .get(&logout_url(tokens["id_token"].as_str().unwrap()))
        .await;
    assert!(!browser.has_session());
    let (status, body) = f
        .refresh(tokens["refresh_token"].as_str().unwrap(), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn revoking_sessions_notifies_too() {
    let f = Fixture::new().await;
    let (_rp, uri) = MockRp::start().await;
    set_uri(&f, Some(&uri)).await;
    let (_browser, _) = f.web_tokens("openid", "ann@example.com").await;
    let admin = user_with_roles(
        &f.db,
        f.tenant.id,
        "admin@example.com",
        &[DirectoryRole::GlobalAdmin],
    )
    .await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &admin).await;
    let path = format!("/api/v1/users/{}/revoke-sessions", f.user.id);
    let (status, body) = call(&f.app, Method::POST, &path, Some(&token), None).await;
    assert!(status.is_success(), "{status} {body}");
    let rows = queued(&f).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].recipient, f.web.id.to_string());
}

#[tokio::test]
async fn settings_uri_validation_and_discovery() {
    let f = Fixture::new().await;
    let admin = user_with_roles(
        &f.db,
        f.tenant.id,
        "admin@example.com",
        &[DirectoryRole::GlobalAdmin],
    )
    .await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &admin).await;

    let (status, body) = call(&f.app, Method::GET, "/api/v1/settings", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["logout_revokes_refresh_tokens"], true);
    let patch = json!({ "logout_revokes_refresh_tokens": false });
    let (status, body) = call(
        &f.app,
        Method::PATCH,
        "/api/v1/settings",
        Some(&token),
        Some(&patch),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["logout_revokes_refresh_tokens"], false);

    let app = format!("/api/v1/applications/{}", f.web.id);
    for bad in [
        "http://rp.example/bcl",
        "https://rp.example/bcl#x",
        "not a url",
    ] {
        let body = json!({ "backchannel_logout_uri": bad });
        let (status, _) = call(&f.app, Method::PATCH, &app, Some(&token), Some(&body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let body = json!({
        "backchannel_logout_uri": "https://rp.example/bcl",
        "backchannel_logout_session_required": true,
    });
    let (status, view) = call(&f.app, Method::PATCH, &app, Some(&token), Some(&body)).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["backchannel_logout_uri"], "https://rp.example/bcl");
    assert_eq!(view["backchannel_logout_session_required"], true);
    let clear = json!({ "backchannel_logout_uri": null });
    let (_, view) = call(&f.app, Method::PATCH, &app, Some(&token), Some(&clear)).await;
    assert_eq!(view["backchannel_logout_uri"], Value::Null);

    let (_, text) = get(&f.app, "/.well-known/openid-configuration").await;
    let meta: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(meta["backchannel_logout_supported"], true);
    assert_eq!(meta["backchannel_logout_session_supported"], true);
}
