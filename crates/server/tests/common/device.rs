//! Device authorization grant helpers: the device's back-channel calls and
//! the browser's code entry / confirmation.

use axum::http::StatusCode;
use entity::{applications, device_authorizations};
use sea_orm::{ConnectionTrait, EntityTrait};
use serde_json::{Value, json};

use super::{
    ORIGIN,
    browser::Browser,
    flow::{Fixture, PASSWORD},
};

pub const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Turns the device code grant on for `app`.
pub async fn enable(f: &Fixture, app: &applications::Model) {
    f.db.execute_unprepared(&format!(
        "UPDATE applications SET device_code_enabled = true WHERE id = '{}'",
        app.id
    ))
    .await
    .unwrap();
}

/// Client auth form fields: Basic for a confidential client, else `client_id`.
fn auth<'a>(
    app: &'a applications::Model,
    secret: Option<&'a str>,
    form: &mut Vec<(&'a str, &'a str)>,
) -> Option<(&'a str, &'a str)> {
    match secret {
        Some(secret) => Some((app.client_id.as_str(), secret)),
        None => {
            form.push(("client_id", &app.client_id));
            None
        }
    }
}

/// `POST /oauth2/devicecode`.
pub async fn start(
    f: &Fixture,
    app: &applications::Model,
    secret: Option<&str>,
    scope: &str,
) -> (StatusCode, Value) {
    let mut form = vec![("scope", scope)];
    let basic = auth(app, secret, &mut form);
    let (status, _, body) = f.post_form("/oauth2/devicecode", &form, basic).await;
    (status, body)
}

/// One poll of the token endpoint.
pub async fn poll(
    f: &Fixture,
    app: &applications::Model,
    secret: Option<&str>,
    device_code: &str,
) -> (StatusCode, Value) {
    let mut form = vec![("grant_type", GRANT), ("device_code", device_code)];
    let basic = auth(app, secret, &mut form);
    let (status, _, body) = f.post_form("/oauth2/token", &form, basic).await;
    (status, body)
}

/// Lets the next poll count as on time (instead of waiting the interval).
pub async fn forget_last_poll(f: &Fixture) {
    f.db.execute_unprepared("UPDATE device_authorizations SET last_polled_at = NULL")
        .await
        .unwrap();
}

pub async fn rows(f: &Fixture) -> Vec<device_authorizations::Model> {
    device_authorizations::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
}

/// `POST /api/authn/device` from the verification page.
pub async fn enter(browser: &mut Browser, user_code: &str) -> (StatusCode, Value) {
    let (status, _, body) = browser
        .post_json(
            "/api/authn/device",
            &json!({ "user_code": user_code }),
            ORIGIN,
        )
        .await;
    (status, body)
}

/// Enters the code and returns the login transaction it started.
pub async fn enter_tx(browser: &mut Browser, user_code: &str) -> String {
    let (status, body) = enter(browser, user_code).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let url = body["redirect"].as_str().unwrap();
    url.strip_prefix(&format!("{ORIGIN}/login?tx="))
        .unwrap_or_else(|| panic!("not a login URL: {url}"))
        .to_owned()
}

/// Signs in with the password; returns the step view that follows.
pub async fn sign_in(browser: &mut Browser, tx: &str, email: &str) -> Value {
    let (status, view) = browser
        .step(
            tx,
            "password",
            json!({ "email": email, "password": PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    view
}

/// Answers the confirmation step; returns the final redirect URL.
pub async fn decide(browser: &mut Browser, tx: &str, view: &Value, approve: bool) -> String {
    assert_eq!(view["step"], "consent", "{view}");
    assert_eq!(view["device"], true, "{view}");
    let scopes: Vec<Value> = view["consent"]["scopes"]
        .as_array()
        .map(|s| s.iter().map(|s| s["value"].clone()).collect())
        .unwrap_or_default();
    let (status, body) = browser
        .step(
            tx,
            "consent",
            json!({ "approve": approve, "scopes": scopes }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["redirect"].as_str().unwrap().to_owned()
}

/// The whole browser side for a signed-out browser: code, password, decision.
pub async fn approve_as(f: &Fixture, user_code: &str, email: &str, approve: bool) -> String {
    let mut browser = f.browser();
    let tx = enter_tx(&mut browser, user_code).await;
    let view = sign_in(&mut browser, &tx, email).await;
    decide(&mut browser, &tx, &view, approve).await
}
