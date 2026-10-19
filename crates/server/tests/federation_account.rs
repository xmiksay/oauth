//! Linked identities from the account side: My Account linking (bound to
//! the browser) and unlinking, the admin view and unlink, and the
//! last-sign-in-method rule counting identities.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{
    ORIGIN,
    browser::Browser,
    federation::{Fed, follow},
    flow::{Fixture, PASSWORD},
    mgmt::{audited, call, mint_user_token},
    upstream::Account,
};
use oauth_server::directory;
use serde_json::{Value, json};

const ME: &str = "/api/v1/me/identities";

/// A bearer call made by `browser` (so it keeps the cookies it is sent).
async fn me_call(
    browser: &mut Browser,
    token: &str,
    method: Method,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _, text) = browser.request(req).await;
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

fn security(query: &str) -> String {
    format!("{ORIGIN}/myaccount/security?{query}")
}

#[tokio::test]
async fn users_link_from_my_account_in_their_own_browser_only() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({ "policy": "deny" })).await;
    let token = mint_user_token(&fed.f.db, &fed.f.config, &fed.f.tenant, &fed.f.user).await;
    let mut browser = fed.f.browser();
    let link = format!("{ME}/{idp}/link");
    let (status, _) = me_call(
        &mut browser,
        &token,
        Method::POST,
        &link,
        json!({ "password": "wrong" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let reauth = json!({ "password": PASSWORD });
    let (status, body) = me_call(&mut browser, &token, Method::POST, &link, reauth.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Completed in another browser: refused (link CSRF).
    let callback = fed.up.authorize(body["redirect"].as_str().unwrap());
    let mut other = Browser::new(fed.f.app.clone());
    assert_eq!(
        follow(&mut other, &callback).await,
        format!("{ORIGIN}/login?error=upstream_failed")
    );
    let (_, body) = me_call(&mut browser, &token, Method::POST, &link, reauth.clone()).await;
    let location = fed
        .come_back(&mut browser, body["redirect"].as_str().unwrap())
        .await;
    assert_eq!(location, security("federation=linked"));
    let (status, list) = me_call(&mut browser, &token, Method::GET, ME, Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert_eq!(list["items"][0]["idp_name"], "Upstream");
    assert!(list["items"][0].get("subject").is_none());
    assert_eq!(list["available"], json!([]));
    let events = audited(&fed.f.db, "user.identity_link", fed.f.user.id).await;
    assert_eq!(events.last().unwrap()["via"], "me");
    // Policy `deny` lets linked identities in.
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(fed.amr(&location).await, ["fed"]);
    let (status, _) = me_call(&mut browser, &token, Method::POST, &link, reauth.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT, "one identity per provider");
    let id = list["items"][0]["id"].as_str().unwrap().to_owned();
    let path = format!("{ME}/{id}");
    let (status, _) = me_call(
        &mut browser,
        &token,
        Method::DELETE,
        &path,
        json!({ "password": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = me_call(&mut browser, &token, Method::DELETE, &path, reauth).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let events = audited(&fed.f.db, "user.identity_unlink", fed.f.user.id).await;
    assert_eq!(events[0]["via"], "me");
}

#[tokio::test]
async fn an_identity_belongs_to_one_user() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    // JIT: upstream-sub-1 now belongs to a new user.
    fed.sign_in(&mut fed.f.browser(), &idp).await;
    let token = mint_user_token(&fed.f.db, &fed.f.config, &fed.f.tenant, &fed.f.user).await;
    let mut browser = fed.f.browser();
    let link = format!("{ME}/{idp}/link");
    let (_, body) = me_call(
        &mut browser,
        &token,
        Method::POST,
        &link,
        json!({ "password": PASSWORD }),
    )
    .await;
    let location = fed
        .come_back(&mut browser, body["redirect"].as_str().unwrap())
        .await;
    assert_eq!(location, security("federation_error=already_linked"));
    // Upstream failures surface generically there too.
    fed.up.tweak(common::upstream::Tweak::Nonce("x".into()));
    fed.up
        .set_account(Account::new("fresh", "fresh@upstream.example"));
    let (_, body) = me_call(
        &mut browser,
        &token,
        Method::POST,
        &link,
        json!({ "password": PASSWORD }),
    )
    .await;
    let location = fed
        .come_back(&mut browser, body["redirect"].as_str().unwrap())
        .await;
    assert_eq!(location, security("federation_error=upstream_failed"));
    let failures = audited(&fed.f.db, "user.identity_link", fed.f.user.id).await;
    let reasons: Vec<&str> = failures
        .iter()
        .map(|d| d["reason"].as_str().unwrap())
        .collect();
    assert_eq!(reasons, ["already_linked", "id_token_nonce"]);
}

#[tokio::test]
async fn identities_count_as_a_sign_in_method() {
    let fed = Fed::with(Fixture::with_email().await).await;
    let idp = fed.idp(json!({})).await;
    fed.sign_in(&mut fed.f.browser(), &idp).await;
    let user = directory::find_user_by_email(&fed.f.db, fed.f.tenant.id, "pat@upstream.example")
        .await
        .unwrap()
        .unwrap();
    let app = &fed.f.app;
    let detail_path = format!("/api/v1/users/{}", user.id);
    let (_, detail) = call(app, Method::GET, &detail_path, Some(&fed.admin), None).await;
    let identities = detail["identities"].as_array().unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0]["subject"], "upstream-sub-1");
    // Past the invitation stage: the identity is a way in.
    let invite = format!("{detail_path}/invite");
    let (status, _) = call(app, Method::POST, &invite, Some(&fed.admin), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    // The last way in can't be unlinked …
    let unlink = format!(
        "{detail_path}/identities/{}",
        identities[0]["id"].as_str().unwrap()
    );
    let (status, body) = call(app, Method::DELETE, &unlink, Some(&fed.admin), None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    // … until the user has another one.
    let reset = format!("{detail_path}/reset-password");
    let (status, _) = call(
        app,
        Method::POST,
        &reset,
        Some(&fed.admin),
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(app, Method::DELETE, &unlink, Some(&fed.admin), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let events = audited(&fed.f.db, "user.identity_unlink", user.id).await;
    assert_eq!(events[0]["via"], "admin");
    let (status, _) = call(app, Method::DELETE, &unlink, Some(&fed.admin), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
