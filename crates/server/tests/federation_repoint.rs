//! Repointing an identity provider (issuer, client id, discovery URL):
//! links, parked logins and round trips go, the stored secret doesn't
//! follow a move, and work in flight against the old configuration never
//! lands. Plus a parked link that can no longer be made at completion.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{
    ORIGIN,
    browser::{Browser, current_totp},
    federation::{Fed, IDPS, is_login_page, login_error},
    flow::PASSWORD,
    mgmt::{audited, audited_any, call, mint_user_token},
    upstream::{Account, CLIENT_SECRET},
};
use entity::user_identities;
use oauth_server::directory;
use sea_orm::{EntityTrait, PaginatorTrait};
use serde_json::{Value, json};
use uuid::Uuid;

async fn linked(fed: &Fed) -> u64 {
    user_identities::Entity::find()
        .count(&fed.f.db)
        .await
        .unwrap()
}

async fn view(browser: &mut Browser, tx: &str) -> Value {
    let (_, _, body) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    serde_json::from_str(&body).unwrap()
}

async fn update_events(fed: &Fed, idp: &str) -> Vec<Value> {
    let id = Uuid::parse_str(idp).unwrap();
    audited(&fed.f.db, "identity_provider.update", id).await
}

#[tokio::test]
async fn repointing_unlinks_everyone_and_drops_the_secret() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let original = fed.up.issuer.clone();
    fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(linked(&fed).await, 1);
    // Issuer moved without a new secret: unlinked, and the secret is gone.
    let moved = fed
        .patch_idp(&idp, json!({ "issuer": format!("{original}/v2") }))
        .await;
    assert_eq!(
        (
            moved["linked_users"].as_u64(),
            moved["has_secret"].as_bool()
        ),
        (Some(0), Some(false))
    );
    let event = update_events(&fed, &idp).await.pop().unwrap();
    assert_eq!(event["identities_removed"], 1);
    assert_eq!(event["fields"], json!(["issuer", "client_secret"]));
    // Moved back with a secret: kept. The old subject is a stranger now.
    let back = json!({ "issuer": original, "client_secret": CLIENT_SECRET });
    assert_eq!(fed.patch_idp(&idp, back).await["has_secret"], true);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(login_error(&location).as_deref(), Some("account_exists"));
    // A discovery URL change repoints too (same effective URL here).
    fed.up
        .set_account(Account::new("s2", "two@upstream.example"));
    fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(linked(&fed).await, 1);
    let url = format!("{original}/.well-known/openid-configuration");
    let moved = fed.patch_idp(&idp, json!({ "discovery_url": url })).await;
    assert_eq!(
        (
            moved["linked_users"].as_u64(),
            moved["has_secret"].as_bool()
        ),
        (Some(0), Some(false))
    );
    // A new client id unlinks but keeps the secret (same provider).
    let fixed = json!({ "client_secret": CLIENT_SECRET, "discovery_url": null });
    fed.patch_idp(&idp, fixed).await;
    fed.up
        .set_account(Account::new("s4", "four@upstream.example"));
    fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(linked(&fed).await, 1);
    let moved = fed
        .patch_idp(&idp, json!({ "client_id": "other-rp" }))
        .await;
    assert_eq!(
        (
            moved["linked_users"].as_u64(),
            moved["has_secret"].as_bool()
        ),
        (Some(0), Some(true))
    );
    // Other fields leave links and secret alone.
    fed.patch_idp(&idp, json!({ "client_id": common::upstream::CLIENT_ID }))
        .await;
    fed.up
        .set_account(Account::new("s3", "three@upstream.example"));
    fed.sign_in(&mut fed.f.browser(), &idp).await;
    let renamed = fed.patch_idp(&idp, json!({ "name": "Renamed" })).await;
    assert_eq!(
        (
            renamed["linked_users"].as_u64(),
            renamed["has_secret"].as_bool()
        ),
        (Some(1), Some(true))
    );
    assert_eq!(
        update_events(&fed, &idp).await.pop().unwrap()["identities_removed"],
        0
    );
}

#[tokio::test]
async fn parked_logins_are_released_by_a_repoint() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({ "policy": "link_only" })).await;
    let mut browser = fed.f.browser();
    let (tx, location) = fed.sign_in(&mut browser, &idp).await;
    assert!(is_login_page(&location, &tx));
    assert_eq!(view(&mut browser, &tx).await["step"], "link");
    let url = format!("{}/.well-known/openid-configuration", fed.up.issuer);
    fed.patch_idp(
        &idp,
        json!({ "discovery_url": url, "client_secret": CLIENT_SECRET }),
    )
    .await;
    assert_eq!(view(&mut browser, &tx).await["step"], "password");
    let body = json!({ "email": "ann@example.com", "password": PASSWORD });
    let (_, resp) = browser.step(&tx, "password", body).await;
    assert!(resp["redirect"].is_string(), "{resp}");
    assert_eq!(linked(&fed).await, 0);
}

#[tokio::test]
async fn a_link_that_fails_at_completion_still_signs_in() {
    let fed = Fed::new().await;
    fed.f.enroll_totp(&fed.f.user).await;
    let idp = fed.idp(json!({ "policy": "link_only" })).await;
    let mut browser = fed.f.browser();
    let (tx, _) = fed.sign_in(&mut browser, &idp).await;
    let body = json!({ "email": "ann@example.com", "password": PASSWORD });
    let (_, resp) = browser.step(&tx, "password", body).await;
    assert_eq!(resp["step"], "mfa", "{resp}");
    fed.patch_idp(&idp, json!({ "enabled": false })).await;
    let (status, resp) = browser
        .step(&tx, "totp", json!({ "code": current_totp() }))
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        fed.amr(resp["redirect"].as_str().unwrap()).await,
        ["pwd", "otp", "mfa"]
    );
    assert_eq!(linked(&fed).await, 0);
    let events = audited(&fed.f.db, "user.identity_link", fed.f.user.id).await;
    assert_eq!(events.last().unwrap()["reason"], "link_unavailable");
}

async fn patch(app: Router, token: String, path: String, body: Value) {
    let (status, out) = call(&app, Method::PATCH, &path, Some(&token), Some(&body)).await;
    assert_eq!(status, StatusCode::OK, "{out}");
}

#[tokio::test]
async fn a_repoint_during_the_exchange_wins() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let (app, token, path) = (
        fed.f.app.clone(),
        fed.admin.clone(),
        format!("{IDPS}/{idp}"),
    );
    fed.up.on_token(Box::new(move || {
        Box::pin(patch(app, token, path, json!({ "client_id": "moved" })))
    }));
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    let events = audited_any(&fed.f.db, "sign_in").await;
    assert_eq!(events.last().unwrap()["reason"], "idp_repointed");
    let found = directory::find_user_by_email(&fed.f.db, fed.f.tenant.id, "pat@upstream.example")
        .await
        .unwrap();
    assert!(
        found.is_none(),
        "nothing provisioned for the old configuration"
    );
}

#[tokio::test]
async fn a_session_revoked_during_the_exchange_cancels_the_link() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let token = mint_user_token(&fed.f.db, &fed.f.config, &fed.f.tenant, &fed.f.user).await;
    let mut browser = fed.f.browser();
    let req = Request::post(format!("/api/v1/me/identities/{idp}/link"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "password": PASSWORD }).to_string()))
        .unwrap();
    let (status, _, text) = browser.request(req).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let redirect: Value = serde_json::from_str(&text).unwrap();
    let db = fed.f.db.clone();
    fed.up.on_token(Box::new(move || {
        Box::pin(async move {
            use sea_orm::ConnectionTrait;
            db.execute_unprepared("DELETE FROM sessions").await.unwrap();
        })
    }));
    let location = fed
        .come_back(&mut browser, redirect["redirect"].as_str().unwrap())
        .await;
    assert_eq!(
        location,
        format!("{ORIGIN}/myaccount/security?federation_error=session_ended")
    );
    assert_eq!(linked(&fed).await, 0);
}
