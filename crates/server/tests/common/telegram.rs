//! Fake Telegram Bot API (in-process axum server capturing calls) and
//! helpers to drive the bot webhook and link a user's chat.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU16, Ordering},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{Method, Request, StatusCode},
    routing::post,
};
use entity::users;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use super::{
    browser::{Browser, authorize_url, send},
    flow::{Fixture, PASSWORD, WEB_CB},
    mgmt::{call, mint_user_token},
};

pub const BOT_TOKEN: &str = "4242:test-bot-token_XYZ";
pub const BOT_USERNAME: &str = "oauth_test_bot";
pub const WEBHOOK_SECRET: &str = "hook-secret_0123";
/// The chat the login helpers link.
pub const CHAT: i64 = 7_770_001;
const ANN: &str = "ann@example.com";
/// The apex host (the webhook lives there).
pub const APEX: &str = "https://id.example.test";

/// One captured Bot API call.
#[derive(Clone, Debug)]
pub struct Call {
    /// The `bot{token}` path segment.
    pub bot: String,
    pub method: String,
    pub body: Value,
}

#[derive(Clone, Default)]
struct Shared {
    calls: Arc<Mutex<Vec<Call>>>,
    /// Non-zero: answer every call with this status (`ok: false`).
    fail: Arc<AtomicU16>,
}

pub struct FakeBot {
    pub url: String,
    shared: Shared,
}

async fn handle(
    State(shared): State<Shared>,
    Path((bot, method)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    shared
        .calls
        .lock()
        .unwrap()
        .push(Call { bot, method, body });
    match shared.fail.load(Ordering::SeqCst) {
        0 => (StatusCode::OK, Json(json!({ "ok": true, "result": true }))),
        code => (
            StatusCode::from_u16(code).unwrap(),
            Json(json!({ "ok": false, "error_code": code, "description": "nope" })),
        ),
    }
}

impl FakeBot {
    pub async fn start() -> Self {
        let shared = Shared::default();
        let app = Router::new()
            .route("/{bot}/{method}", post(handle))
            .with_state(shared.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, shared }
    }

    pub fn calls(&self) -> Vec<Call> {
        self.shared.calls.lock().unwrap().clone()
    }

    /// `sendMessage` calls as `(chat_id, text)`, and forgets them.
    pub fn take_messages(&self) -> Vec<(i64, String)> {
        let mut calls = self.shared.calls.lock().unwrap();
        let out = calls
            .iter()
            .filter(|c| c.method == "sendMessage")
            .map(|c| {
                (
                    c.body["chat_id"].as_i64().unwrap(),
                    c.body["text"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        calls.clear();
        out
    }

    /// Makes every later call fail with `status` (0 = succeed again).
    pub fn fail_with(&self, status: u16) {
        self.shared.fail.store(status, Ordering::SeqCst);
    }
}

/// Environment for a Telegram-enabled server talking to `bot`.
pub fn env(bot: &FakeBot) -> Vec<(&'static str, String)> {
    vec![
        ("TELEGRAM_BOT_TOKEN", BOT_TOKEN.to_owned()),
        ("TELEGRAM_BOT_USERNAME", BOT_USERNAME.to_owned()),
        ("TELEGRAM_WEBHOOK_SECRET", WEBHOOK_SECRET.to_owned()),
        ("TELEGRAM_API_URL", bot.url.clone()),
    ]
}

/// A private-chat text message update from `chat_id`.
pub fn message(chat_id: i64, chat_type: &str, text: &str) -> Value {
    json!({
        "update_id": 1,
        "message": {
            "message_id": 7,
            "date": 1_700_000_000,
            "chat": { "id": chat_id, "type": chat_type },
            "from": { "id": chat_id, "is_bot": false, "first_name": "Ann", "username": "ann_tg" },
            "text": text,
        }
    })
}

impl Fixture {
    /// POSTs an update to the webhook on the apex host with `secret`.
    pub async fn webhook_with(&self, secret: Option<&str>, update: &Value) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(format!("{APEX}/telegram/webhook"))
            .header("content-type", "application/json");
        if let Some(secret) = secret {
            req = req.header("x-telegram-bot-api-secret-token", secret);
        }
        let req = req.body(Body::from(update.to_string())).unwrap();
        let (status, _, text) = send(&self.app, req).await;
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// [`Self::webhook_with`] with the right secret; `text` = the bot's reply.
    pub async fn bot_says(&self, chat_id: i64, chat_type: &str, text: &str) -> Option<String> {
        let (status, reply) = self
            .webhook_with(Some(WEBHOOK_SECRET), &message(chat_id, chat_type, text))
            .await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        if reply.is_null() {
            return None;
        }
        assert_eq!(reply["method"], "sendMessage");
        assert_eq!(reply["chat_id"], chat_id);
        Some(reply["text"].as_str().unwrap().to_owned())
    }

    /// `POST me/telegram/link` (password re-auth) → the start code.
    pub async fn link_code(&self, token: &str) -> String {
        let (status, body) = call(
            &self.app,
            Method::POST,
            "/api/v1/me/telegram/link",
            Some(token),
            Some(&json!({ "password": PASSWORD })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let url = body["url"].as_str().unwrap();
        let prefix = format!("https://t.me/{BOT_USERNAME}?start=");
        url.strip_prefix(&prefix)
            .unwrap_or_else(|| panic!("{url}"))
            .to_owned()
    }

    /// Links `user`'s account to `chat_id` through My Account + `/start`.
    pub async fn link_telegram(&self, user: &users::Model, chat_id: i64) {
        let token = mint_user_token(&self.db, &self.config, &self.tenant, user).await;
        let code = self.link_code(&token).await;
        let reply = self
            .bot_says(chat_id, "private", &format!("/start {code}"))
            .await
            .unwrap();
        assert!(reply.contains("now linked"), "{reply}");
    }
}

/// A browser past the password step: `(browser, tx, step view)`.
pub async fn at_mfa(f: &Fixture) -> (Browser, String, Value) {
    let mut browser = f.browser();
    let url = authorize_url("web-app", WEB_CB, "openid", &[]);
    let tx = browser.authorize(&url).await.unwrap();
    let (status, view) = browser
        .step(
            &tx,
            "password",
            json!({ "email": ANN, "password": PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    (browser, tx, view)
}

pub async fn send_code(browser: &mut Browser, tx: &str) -> (StatusCode, Value) {
    browser.step(tx, "telegram/send", json!({})).await
}

/// Sends a code and returns it as the chat received it.
pub async fn sent_code(f: &Fixture, browser: &mut Browser, tx: &str) -> String {
    let (status, body) = send_code(browser, tx).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "sent": true, "expires_in": 300 }));
    let messages = f.bot().take_messages();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].0, CHAT);
    let code: String = messages[0].1.chars().take(6).collect();
    assert!(
        code.bytes().all(|b| b.is_ascii_digit()),
        "{}",
        messages[0].1
    );
    assert!(messages[0].1.contains("Contoso"));
    code
}

pub async fn linked() -> Fixture {
    let f = Fixture::with_telegram(false).await;
    f.link_telegram(&f.user, CHAT).await;
    f.bot().take_messages();
    f
}
