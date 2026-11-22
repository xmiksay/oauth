// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! An administrator setting `email_verified` on create and PATCH (#47).
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mail::{only_to, token_in},
    mgmt::{audited, call, mint_user_token, user_with_roles},
};
use entity::enums::DirectoryRole::{GlobalAdmin, UserAdmin};
use serde_json::{Value, json};

const USERS: &str = "/api/v1/users";

async fn admin_token(f: &Fixture) -> String {
    let admin = user_with_roles(&f.db, f.tenant.id, "admin@example.com", &[UserAdmin]).await;
    mint_user_token(&f.db, &f.config, &f.tenant, &admin).await
}

fn id_of(user: &Value) -> uuid::Uuid {
    user["id"].as_str().unwrap().parse().unwrap()
}

#[tokio::test]
async fn create_verified_sends_no_verification_link() {
    let f = Fixture::with_email().await;
    let token = admin_token(&f).await;
    let tok = Some(token.as_str());
    let body =
        json!({ "email": "vera@example.com", "display_name": "Vera", "email_verified": true });
    let (status, created) = call(&f.app, Method::POST, USERS, tok, Some(&body)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["user"]["email_verified"], true);
    let sent = f.deliver().await;
    assert!(sent.iter().all(|m| m.to != "vera@example.com"));
    let id = id_of(&created["user"]);
    assert_eq!(
        audited(&f.db, "user.create", id).await[0]["email_verified"],
        true
    );

    // The default stays unverified, with a verification link.
    let body = json!({ "email": "walt@example.com", "display_name": "Walt" });
    let (status, created) = call(&f.app, Method::POST, USERS, tok, Some(&body)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["user"]["email_verified"], false);
    only_to(&f.deliver().await, "walt@example.com");
}

#[tokio::test]
async fn patch_toggles_and_overrides_the_email_change_reset() {
    let f = Fixture::with_email().await;
    let token = admin_token(&f).await;
    let tok = Some(token.as_str());
    let body = json!({ "email": "vera@example.com", "display_name": "Vera" });
    let (_, created) = call(&f.app, Method::POST, USERS, tok, Some(&body)).await;
    let id = id_of(&created["user"]);
    let path = format!("{USERS}/{id}");
    f.deliver().await;

    let (status, user) = call(
        &f.app,
        Method::PATCH,
        &path,
        tok,
        Some(&json!({ "email_verified": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{user}");
    assert_eq!(user["email_verified"], true);
    let events = audited(&f.db, "user.update", id).await;
    assert_eq!(events[0]["fields"], json!(["email_verified"]));

    // Unchanged value: no write, no audit event.
    let unchanged = Some(json!({ "email_verified": true }));
    let (status, _) = call(&f.app, Method::PATCH, &path, tok, unchanged.as_ref()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audited(&f.db, "user.update", id).await.len(), 1);

    // A new address alone resets the flag and mails a verification link.
    let body = json!({ "email": "vera2@example.com" });
    let (_, user) = call(&f.app, Method::PATCH, &path, tok, Some(&body)).await;
    assert_eq!(user["email_verified"], false);
    only_to(&f.deliver().await, "vera2@example.com");

    // Set explicitly in the same request, the flag wins and no link is sent.
    let body = json!({ "email": "vera3@example.com", "email_verified": true });
    let (_, user) = call(&f.app, Method::PATCH, &path, tok, Some(&body)).await;
    assert_eq!(user["email_verified"], true);
    let sent = f.deliver().await;
    assert!(sent.iter().all(|m| m.to != "vera3@example.com"));
    let events = audited(&f.db, "user.update", id).await;
    assert_eq!(
        events.last().unwrap()["fields"],
        json!(["email", "email_verified"])
    );

    let body = json!({ "email_verified": false });
    let (_, user) = call(&f.app, Method::PATCH, &path, tok, Some(&body)).await;
    assert_eq!(user["email_verified"], false);
}

#[tokio::test]
async fn needs_users_write_and_rank_over_the_target() {
    let f = Fixture::new().await;
    let token = admin_token(&f).await;
    let global = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let body = json!({ "email_verified": true });
    let path = format!("{USERS}/{}", global.id);
    let (status, _) = call(&f.app, Method::PATCH, &path, Some(&token), Some(&body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let plain = user_with_roles(&f.db, f.tenant.id, "plain@example.com", &[]).await;
    let plain_token = mint_user_token(&f.db, &f.config, &f.tenant, &plain).await;
    let path = format!("{USERS}/{}", plain.id);
    let (status, _) = call(
        &f.app,
        Method::PATCH,
        &path,
        Some(&plain_token),
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let create = json!({ "email": "c@example.com", "display_name": "C", "email_verified": true });
    let (status, _) = call(
        &f.app,
        Method::POST,
        USERS,
        Some(&plain_token),
        Some(&create),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn email_change_explicitly_unverified_mails_a_verification_link() {
    let f = Fixture::with_email().await;
    let token = admin_token(&f).await;
    let tok = Some(token.as_str());
    let body =
        json!({ "email": "vera@example.com", "display_name": "Vera", "email_verified": true });
    let (_, created) = call(&f.app, Method::POST, USERS, tok, Some(&body)).await;
    let path = format!("{USERS}/{}", id_of(&created["user"]));
    f.deliver().await;

    let body = json!({ "email": "vera2@example.com", "email_verified": false });
    let (status, user) = call(&f.app, Method::PATCH, &path, tok, Some(&body)).await;
    assert_eq!(status, StatusCode::OK, "{user}");
    assert_eq!(user["email_verified"], false);
    let sent = f.deliver().await;
    token_in(
        only_to(&sent, "vera2@example.com"),
        "/myaccount/verify-email",
    );
}

#[tokio::test]
async fn invited_user_gets_a_fresh_invite_even_when_marked_verified() {
    let f = Fixture::with_email().await;
    let token = admin_token(&f).await;
    let tok = Some(token.as_str());
    let body = json!({
        "email": "ivy@example.com", "display_name": "Ivy",
        "invite": true, "email_verified": true
    });
    let (status, created) = call(&f.app, Method::POST, USERS, tok, Some(&body)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["user"]["email_verified"], true);
    token_in(
        only_to(&f.deliver().await, "ivy@example.com"),
        "/login/invite",
    );

    // The echoed `true` is no change: the new address resets to unverified.
    let path = format!("{USERS}/{}", id_of(&created["user"]));
    let body = json!({ "email": "ivy2@example.com", "email_verified": true });
    let (status, user) = call(&f.app, Method::PATCH, &path, tok, Some(&body)).await;
    assert_eq!(status, StatusCode::OK, "{user}");
    assert_eq!(user["email_verified"], false);
    token_in(
        only_to(&f.deliver().await, "ivy2@example.com"),
        "/login/invite",
    );
}

#[tokio::test]
async fn echoed_verified_with_a_new_email_still_resets_it() {
    let f = Fixture::with_email().await;
    let token = admin_token(&f).await;
    let tok = Some(token.as_str());
    let body = json!({
        "email": "vera@example.com", "display_name": "Vera",
        "password": "correct horse battery staple", "email_verified": true
    });
    let (status, created) = call(&f.app, Method::POST, USERS, tok, Some(&body)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = id_of(&created["user"]);
    let path = format!("{USERS}/{id}");
    f.deliver().await;

    // A client echoing the full object: `true` is the stored value, not a
    // vouch for the new address.
    let body = json!({ "email": "vera2@example.com", "email_verified": true });
    let (status, user) = call(&f.app, Method::PATCH, &path, tok, Some(&body)).await;
    assert_eq!(status, StatusCode::OK, "{user}");
    assert_eq!(user["email_verified"], false);
    let sent = f.deliver().await;
    token_in(
        only_to(&sent, "vera2@example.com"),
        "/myaccount/verify-email",
    );
    let events = audited(&f.db, "user.update", id).await;
    assert_eq!(events.last().unwrap()["fields"], json!(["email"]));

    // Vouching for the new address takes a real switch.
    let body = json!({ "email_verified": true });
    let (_, user) = call(&f.app, Method::PATCH, &path, tok, Some(&body)).await;
    assert_eq!(user["email_verified"], true);
    let events = audited(&f.db, "user.update", id).await;
    assert_eq!(events.last().unwrap()["fields"], json!(["email_verified"]));
}
