// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Accepting an invitation with a passkey instead of a password.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    ORIGIN,
    authenticator::{Alg, Authenticator, Tweak},
    browser::authorize_url,
    flow::{Fixture, T, WEB_CB},
    mail::{only_to, token_in},
    mgmt::{audited, call, mint_user_token, user_with_roles},
    passkeys::login_step,
};
use entity::{enums::DirectoryRole, users};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait};
use serde_json::{Value, json};
use uuid::Uuid;

const OPTIONS: &str = "/api/authn/email/invite/passkey/options";
const ACCEPT: &str = "/api/authn/email/invite/passkey";

async fn post(f: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let (status, _, body) = f.browser().post_json(path, &body, ORIGIN).await;
    (status, body)
}

/// Invites `email`; returns the admin token, the user id and the link token.
async fn invite(f: &Fixture, email: &str) -> (String, Uuid, String) {
    let admin = user_with_roles(
        &f.db,
        f.tenant.id,
        "admin@example.com",
        &[DirectoryRole::UserAdmin],
    )
    .await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &admin).await;
    let body = json!({ "email": email, "display_name": "New", "invite": true });
    let (status, created) = call(
        &f.app,
        Method::POST,
        "/api/v1/users",
        Some(&token),
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["user"]["id"].as_str().unwrap().parse().unwrap();
    let link = token_in(only_to(&f.deliver().await, email), "/login/invite");
    (token, id, link)
}

async fn user(f: &Fixture, id: Uuid) -> users::Model {
    users::Entity::find_by_id(id)
        .one(&f.db)
        .await
        .unwrap()
        .unwrap()
}

async fn accept(
    f: &Fixture,
    link: &str,
    auth: &mut Authenticator,
    tweak: &Tweak,
) -> (StatusCode, Value) {
    let (status, options) = post(f, OPTIONS, json!({ "token": link })).await;
    if status != StatusCode::OK {
        return (status, options);
    }
    let credential = auth.create(&options, tweak);
    post(
        f,
        ACCEPT,
        json!({ "token": link, "credential": credential, "name": "Phone" }),
    )
    .await
}

#[tokio::test]
async fn an_invitation_accepted_with_a_passkey_signs_in_passwordless() {
    let f = Fixture::with_email().await;
    let (admin_token, id, link) = invite(&f, "new@example.com").await;
    let mut auth = Authenticator::new(Alg::Es256, T);

    // A rejected credential leaves the link usable.
    let wrong = Tweak {
        origin: Some("https://evil.example".into()),
        ..Tweak::default()
    };
    let (status, body) = accept(&f, &link, &mut auth, &wrong).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_request"))
    );

    let (status, body) = accept(&f, &link, &mut auth, &Tweak::default()).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let invited = user(&f, id).await;
    assert!(invited.email_verified && invited.password_hash.is_none());
    assert_eq!(invited.webauthn_handle.as_ref().map(Vec::len), Some(32));
    assert_eq!(
        audited(&f.db, "user.invite_accept", id).await,
        vec![json!({ "method": "passkey" })]
    );
    assert_eq!(
        audited(&f.db, "user.mfa.passkey_register", id).await[0]["via"],
        "invite"
    );

    // Spent: neither variant takes the link again, and no new invitation.
    let (status, body) = post(&f, OPTIONS, json!({ "token": link })).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_token"))
    );
    let set = json!({ "token": link, "new_password": "my first passphrase" });
    assert_eq!(
        post(&f, "/api/authn/email/invite", set).await.0,
        StatusCode::BAD_REQUEST
    );
    let resend = format!("/api/v1/users/{id}/invite");
    let (status, _) = call(&f.app, Method::POST, &resend, Some(&admin_token), None).await;
    assert_eq!(status, StatusCode::CONFLICT);

    let mut browser = f.browser();
    let tx = browser
        .authorize(&authorize_url("web-app", WEB_CB, "openid", &[]))
        .await
        .unwrap();
    let (status, resp) = login_step(&mut browser, &tx, &mut auth, &Tweak::default()).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(resp["redirect"].as_str().unwrap().starts_with(WEB_CB));
}

#[tokio::test]
async fn invitation_passkeys_obey_the_link_rules() {
    let f = Fixture::with_email().await;
    let (_, id, link) = invite(&f, "new@example.com").await;
    let mut auth = Authenticator::new(Alg::Es256, T);
    // A register challenge of the invitation's user is what it answers.
    let (_, options) = post(&f, OPTIONS, json!({ "token": link })).await;
    assert_eq!(options["publicKey"]["user"]["name"], "new@example.com");
    let other_token =
        json!({ "token": "x".repeat(43), "credential": auth.create(&options, &Tweak::default()) });
    assert_eq!(
        post(&f, ACCEPT, other_token).await.0,
        StatusCode::BAD_REQUEST
    );

    // Disabled user / changed address: the link is dead.
    let mut row: users::ActiveModel = user(&f, id).await.into();
    row.disabled = Set(true);
    let disabled = row.update(&f.db).await.unwrap();
    assert_eq!(
        post(&f, OPTIONS, json!({ "token": link })).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut row: users::ActiveModel = disabled.into();
    row.disabled = Set(false);
    row.email = Set("moved@example.com".into());
    row.update(&f.db).await.unwrap();
    let (status, _) = accept(&f, &link, &mut auth, &Tweak::default()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(audited(&f.db, "user.invite_accept", id).await.is_empty());
}
