//! Passkey flows over the HTTP API, driven by the software authenticator.

use axum::{
    Router,
    http::{Method, StatusCode},
};
use serde_json::{Value, json};

use entity::users;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectionTrait};

use super::{
    authenticator::{Alg, Authenticator, Tweak},
    browser::{Browser, authorize_url},
    flow::{Fixture, PASSWORD, T, WEB_CB},
    mgmt::{audited, call, mint_user_token},
};

pub const ME: &str = "/api/v1/me";

/// A call to `{ME}{path}` with the user's bearer token.
pub async fn me_call(
    f: &Fixture,
    token: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    call(
        &f.app,
        method,
        &format!("{ME}{path}"),
        Some(token),
        body.as_ref(),
    )
    .await
}

/// `POST me/passkeys/options` with `reauth`, then the authenticator, then
/// `POST me/passkeys`. Returns the final status and body.
pub async fn register(
    f: &Fixture,
    token: &str,
    auth: &mut Authenticator,
    reauth: Value,
    tweak: &Tweak,
) -> (StatusCode, Value) {
    register_at(&f.app, "", token, auth, reauth, tweak).await
}

/// [`register`] against `base` (`""` = the fixture tenant, else another
/// tenant's absolute origin).
pub async fn register_at(
    app: &Router,
    base: &str,
    token: &str,
    auth: &mut Authenticator,
    reauth: Value,
    tweak: &Tweak,
) -> (StatusCode, Value) {
    let (status, options) = call(
        app,
        Method::POST,
        &format!("{base}{ME}/passkeys/options"),
        Some(token),
        Some(&reauth),
    )
    .await;
    if status != StatusCode::OK {
        return (status, options);
    }
    let credential = auth.create(&options, tweak);
    call(
        app,
        Method::POST,
        &format!("{base}{ME}/passkeys"),
        Some(token),
        Some(&json!({ "credential": credential, "name": "Laptop" })),
    )
    .await
}

/// Registers with password re-authentication; asserts 201.
pub async fn register_ok(f: &Fixture, token: &str, auth: &mut Authenticator) -> Value {
    let reauth = json!({ "password": PASSWORD });
    let (status, body) = register(f, token, auth, reauth, &Tweak::default()).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

/// Fetches login options for `tx` and answers them.
pub async fn login_step(
    browser: &mut Browser,
    tx: &str,
    auth: &mut Authenticator,
    tweak: &Tweak,
) -> (StatusCode, Value) {
    let (status, options) = browser.step(tx, "passkey/options", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{options}");
    let assertion = auth.get(&options, tweak);
    browser.step(tx, "passkey", assertion).await
}

/// A re-authentication body proving possession of `auth`.
pub async fn reauth_with(f: &Fixture, token: &str, auth: &mut Authenticator) -> Value {
    let (status, options) = call(
        &f.app,
        Method::POST,
        &format!("{ME}/reauth/options"),
        Some(token),
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    json!({ "passkey": auth.get(&options, &Tweak::default()) })
}

/// An authorize URL for `web-app` asking for `openid` only.
pub fn openid() -> String {
    authorize_url("web-app", WEB_CB, "openid", &[])
}

/// The fixture user with a registered passkey.
pub async fn enrolled(f: &Fixture, alg: Alg) -> Authenticator {
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let mut auth = Authenticator::new(alg, T);
    register_ok(f, &token, &mut auth).await;
    auth
}

/// A passwordless sign-in attempt in a fresh browser and transaction.
pub async fn sign_in(f: &Fixture, auth: &mut Authenticator, tweak: &Tweak) -> (StatusCode, Value) {
    let mut browser = f.browser();
    let tx = browser.authorize(&openid()).await.unwrap();
    login_step(&mut browser, &tx, auth, tweak).await
}

/// `details` of the newest failed sign-in of `user`.
pub async fn last_failure(f: &Fixture, user: &users::Model) -> Value {
    audited(&f.db, "sign_in", user.id)
        .await
        .into_iter()
        .rev()
        .find(|d| d.get("reason").is_some())
        .unwrap()
}

/// One failing case: a fresh transaction answered with `tweak` → 401 with
/// the audited `reason`.
pub async fn refused(f: &Fixture, auth: &mut Authenticator, tweak: Tweak, reason: &str) {
    // Many cases in a row would trip the per-account limit (tested elsewhere).
    f.db.execute_unprepared("DELETE FROM rate_limit_buckets")
        .await
        .unwrap();
    let (status, resp) = sign_in(f, auth, &tweak).await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_credentials")),
        "{reason}: {resp}"
    );
    assert_eq!(last_failure(f, &f.user).await["reason"], reason, "{resp}");
    assert_eq!(last_failure(f, &f.user).await["factor"], "passkey");
}

/// Drops the user's password (as if they had only ever used passkeys).
pub async fn drop_password(f: &Fixture, user: &users::Model) -> users::Model {
    let mut row: users::ActiveModel = user.clone().into();
    row.password_hash = Set(None);
    row.update(&f.db).await.unwrap()
}
