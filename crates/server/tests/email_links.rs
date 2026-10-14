// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Invitations, address verification and self-service email change.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    ORIGIN,
    flow::{Fixture, PASSWORD},
    mail::{only_to, token_in},
    mgmt::{call, mint_user_token, user_with_roles},
};
use entity::{enums::DirectoryRole, users};
use oauth_server::directory::password;
use sea_orm::EntityTrait;
use serde_json::{Value, json};
use uuid::Uuid;

async fn admin_token(f: &Fixture) -> String {
    let admin = user_with_roles(
        &f.db,
        f.tenant.id,
        "admin@example.com",
        &[DirectoryRole::UserAdmin],
    )
    .await;
    mint_user_token(&f.db, &f.config, &f.tenant, &admin).await
}

async fn redeem(f: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let (status, _, body) = f.browser().post_json(path, &body, ORIGIN).await;
    (status, body)
}

async fn user(f: &Fixture, id: Uuid) -> users::Model {
    users::Entity::find_by_id(id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn invite_sets_a_password_and_resend_voids_the_old_link() {
    let f = Fixture::with_email().await;
    let token = admin_token(&f).await;
    let tok = Some(token.as_str());
    let body = json!({ "email": "new@example.com", "display_name": "New", "invite": true, "password": "x".repeat(12) });
    let (status, _) = call(&f.app, Method::POST, "/api/v1/users", tok, Some(&body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body = json!({ "email": "new@example.com", "display_name": "New", "invite": true });
    let (status, created) = call(&f.app, Method::POST, "/api/v1/users", tok, Some(&body)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["invite_sent"], true);
    assert_eq!(created["one_time_password"], Value::Null);
    assert_eq!(created["user"]["has_password"], false);
    let id: Uuid = created["user"]["id"].as_str().unwrap().parse().unwrap();
    let first = token_in(
        only_to(&f.deliver().await, "new@example.com"),
        "/login/invite",
    );

    let resend = format!("/api/v1/users/{id}/invite");
    let (status, _) = call(&f.app, Method::POST, &resend, tok, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let second = token_in(
        only_to(&f.deliver().await, "new@example.com"),
        "/login/invite",
    );
    let set = |t: &str| json!({ "token": t, "new_password": "my first passphrase" });
    let (status, body) = redeem(&f, "/api/authn/email/invite", set(&first)).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_token"))
    );
    // An invite link is not a reset link (and vice versa).
    let (status, _) = redeem(&f, "/api/authn/email/reset", set(&second)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = redeem(&f, "/api/authn/email/invite", set(&second)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let invited = user(&f, id).await;
    assert!(invited.email_verified && !invited.must_change_password);
    assert!(
        password::verify(
            "my first passphrase",
            invited.password_hash.as_deref().unwrap()
        )
        .await
        .unwrap()
    );
    let (status, body) = redeem(&f, "/api/authn/email/invite", set(&second)).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_token"))
    );
    let (status, _) = call(&f.app, Method::POST, &resend, tok, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        common::mgmt::audited(&f.db, "user.invite", id).await.len(),
        2
    );
    assert_eq!(
        common::mgmt::audited(&f.db, "user.invite_accept", id)
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn without_smtp_invites_are_refused_and_one_time_passwords_remain() {
    let f = Fixture::new().await;
    let token = admin_token(&f).await;
    let tok = Some(token.as_str());
    let body = json!({ "email": "new@example.com", "display_name": "New", "invite": true });
    let (status, _) = call(&f.app, Method::POST, "/api/v1/users", tok, Some(&body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body = json!({ "email": "new@example.com", "display_name": "New" });
    let (status, created) = call(&f.app, Method::POST, "/api/v1/users", tok, Some(&body)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        created["one_time_password"].as_str().map(str::len),
        Some(24)
    );
    assert_eq!(created["invite_sent"], false);
    assert_eq!(f.outbox_rows().await, 0);
    let (_, me) = call(&f.app, Method::GET, "/api/v1/me", tok, None).await;
    assert_eq!(me["features"]["email"], false);
}

#[tokio::test]
async fn admin_set_addresses_are_verified_by_link() {
    let f = Fixture::with_email().await;
    let token = admin_token(&f).await;
    let tok = Some(token.as_str());
    let (_, me) = call(&f.app, Method::GET, "/api/v1/me", tok, None).await;
    assert_eq!(me["features"]["email"], true);
    let body = json!({ "email": "dee@example.com", "display_name": "Dee" });
    let (_, created) = call(&f.app, Method::POST, "/api/v1/users", tok, Some(&body)).await;
    let id: Uuid = created["user"]["id"].as_str().unwrap().parse().unwrap();
    let old_link = token_in(
        only_to(&f.deliver().await, "dee@example.com"),
        "/myaccount/verify-email",
    );

    // Changing the address unverifies it, voids links to the old one and
    // sends a fresh link to the new one.
    let path = format!("/api/v1/users/{id}");
    let (status, updated) = call(
        &f.app,
        Method::PATCH,
        &path,
        tok,
        Some(&json!({ "email": "dee2@example.com" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["email_verified"], false);
    let mails = f.deliver().await;
    let link = token_in(
        only_to(&mails, "dee2@example.com"),
        "/myaccount/verify-email",
    );
    let (status, body) = redeem(&f, "/api/authn/email/verify", json!({ "token": old_link })).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_token"))
    );
    let (status, body) = redeem(&f, "/api/authn/email/verify", json!({ "token": link })).await;
    assert_eq!(
        (status, body),
        (
            StatusCode::OK,
            json!({ "purpose": "verify", "email": "dee2@example.com" })
        )
    );
    assert!(user(&f, id).await.email_verified);
    let (status, _) = redeem(&f, "/api/authn/email/verify", json!({ "token": link })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Self-service resend.
    let dee = user(&f, id).await;
    let dee_token = mint_user_token(&f.db, &f.config, &f.tenant, &dee).await;
    let (status, _) = call(
        &f.app,
        Method::POST,
        "/api/v1/me/verify-email",
        Some(&dee_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn email_change_applies_on_verification_and_notifies_the_old_address() {
    let f = Fixture::with_email().await;
    let ann = f.verify(&f.user).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &ann).await;
    let tok = Some(token.as_str());
    let change = |pw: &str, to: &str| json!({ "new_email": to, "password": pw });
    let path = "/api/v1/me/email";
    let (status, _) = call(
        &f.app,
        Method::POST,
        path,
        tok,
        Some(&change("wrong password!", "ann2@example.com")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        &f.app,
        Method::POST,
        path,
        tok,
        Some(&change(PASSWORD, "ANN@example.com")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    common::seed::add_user(&f.db, f.tenant.id, "taken@example.com", false).await;
    // A taken address answers like a free one (no probing for accounts);
    // only applying its link would fail (409).
    let (status, body) = call(
        &f.app,
        Method::POST,
        path,
        tok,
        Some(&change(PASSWORD, "taken@example.com")),
    )
    .await;
    assert_eq!(
        (status, body),
        (StatusCode::ACCEPTED, json!({ "sent": true }))
    );

    let (status, body) = call(
        &f.app,
        Method::POST,
        path,
        tok,
        Some(&change(PASSWORD, "ann2@example.com")),
    )
    .await;
    assert_eq!(
        (status, body),
        (StatusCode::ACCEPTED, json!({ "sent": true }))
    );
    let link = token_in(
        only_to(&f.deliver().await, "ann2@example.com"),
        "/myaccount/verify-email",
    );
    assert_eq!(
        user(&f, ann.id).await.email,
        "ann@example.com",
        "nothing changes before the click"
    );
    let (status, body) = redeem(&f, "/api/authn/email/verify", json!({ "token": link })).await;
    assert_eq!(
        (status, body),
        (
            StatusCode::OK,
            json!({ "purpose": "change", "email": "ann2@example.com" })
        )
    );
    let now = user(&f, ann.id).await;
    assert_eq!(
        (now.email.as_str(), now.email_verified),
        ("ann2@example.com", true)
    );
    let mails = f.deliver().await;
    let notice = only_to(&mails, "ann@example.com");
    assert!(
        notice.subject.contains("email address was changed"),
        "{notice:?}"
    );
    assert!(notice.body.contains("New address: a***@example.com"));
    assert_eq!(
        common::mgmt::audited(&f.db, "user.email_change_complete", ann.id)
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn email_change_conflicts_when_the_address_is_taken_meanwhile() {
    let f = Fixture::with_email().await;
    let ann = f.verify(&f.user).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &ann).await;
    let body = json!({ "new_email": "ann2@example.com", "password": PASSWORD });
    let (status, _) = call(
        &f.app,
        Method::POST,
        "/api/v1/me/email",
        Some(&token),
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let link = token_in(
        only_to(&f.deliver().await, "ann2@example.com"),
        "/myaccount/verify-email",
    );
    common::seed::add_user(&f.db, f.tenant.id, "Ann2@example.com", false).await;
    let (status, body) = redeem(&f, "/api/authn/email/verify", json!({ "token": link })).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("conflict"))
    );
    let unchanged = user(&f, ann.id).await;
    assert_eq!(unchanged.email, "ann@example.com");
    assert!(
        f.deliver().await.is_empty(),
        "no notice for a change that didn't happen"
    );
}
