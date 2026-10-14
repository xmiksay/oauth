// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Passkey re-authentication on the other security endpoints, the per-user
//! cap, and email changes of a passkey-only user.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    authenticator::{Alg, Authenticator},
    flow::{Fixture, PASSWORD, T},
    mail::only_to,
    mgmt::{base32_decode, call, mint_user_token, user_with_roles},
    passkeys::{drop_password, me_call, reauth_with, register_ok},
};
use entity::{enums::DirectoryRole, webauthn_credentials};
use oauth_server::{authn::totp, passkey::store::MAX_PER_USER};
use sea_orm::{ActiveValue::Set, EntityTrait};
use serde_json::json;
use uuid::Uuid;

/// The fixture user, signed in, holding one passkey and no password.
async fn passkey_only(f: &Fixture) -> (String, Authenticator) {
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let mut auth = Authenticator::new(Alg::Es256, T);
    register_ok(f, &token, &mut auth).await;
    drop_password(f, &f.user).await;
    (token, auth)
}

#[tokio::test]
async fn a_passkey_only_user_manages_totp_and_recovery_codes() {
    let f = Fixture::new().await;
    let (token, mut auth) = passkey_only(&f).await;
    let (status, _) = me_call(
        &f,
        &token,
        Method::POST,
        "/totp",
        Some(json!({ "password": PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let reauth = reauth_with(&f, &token, &mut auth).await;
    let (status, begun) = me_call(&f, &token, Method::POST, "/totp", Some(reauth)).await;
    assert_eq!(status, StatusCode::OK, "{begun}");
    let secret = base32_decode(begun["secret"].as_str().unwrap());
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
    let code = format!("{:06}", totp::hotp(&secret, now / totp::STEP_SECS));
    let (status, _) = me_call(
        &f,
        &token,
        Method::POST,
        "/totp/confirm",
        Some(json!({ "code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let reauth = reauth_with(&f, &token, &mut auth).await;
    let (status, codes) = me_call(&f, &token, Method::POST, "/recovery-codes", Some(reauth)).await;
    assert_eq!(
        (status, codes["recovery_codes"].as_array().map(Vec::len)),
        (StatusCode::OK, Some(10))
    );

    let reauth = reauth_with(&f, &token, &mut auth).await;
    let (status, _) = me_call(&f, &token, Method::DELETE, "/totp", Some(reauth.clone())).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // That assertion is spent.
    let (status, _) = me_call(&f, &token, Method::POST, "/totp", Some(reauth)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_passkey_only_user_changes_email_and_an_admin_change_sends_a_verify_link() {
    let f = Fixture::with_email().await;
    let user = f.verify(&f.user).await;
    let (token, mut auth) = passkey_only(&f).await;
    let body = json!({ "new_email": "ann2@example.com", "password": PASSWORD });
    assert_eq!(
        me_call(&f, &token, Method::POST, "/email", Some(body))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let mut body = reauth_with(&f, &token, &mut auth).await;
    body["new_email"] = json!("ann2@example.com");
    let (status, resp) = me_call(&f, &token, Method::POST, "/email", Some(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{resp}");
    let mails = f.deliver().await;
    assert!(
        only_to(&mails, "ann2@example.com")
            .body
            .contains("/myaccount/verify-email#token=")
    );

    // An admin moving a passkey-only user: no invitation (they can sign in).
    let admin = user_with_roles(
        &f.db,
        f.tenant.id,
        "admin@example.com",
        &[DirectoryRole::UserAdmin],
    )
    .await;
    let admin_token = mint_user_token(&f.db, &f.config, &f.tenant, &admin).await;
    let patch = json!({ "email": "moved@example.com" });
    let path = format!("/api/v1/users/{}", user.id);
    let (status, _) = call(
        &f.app,
        Method::PATCH,
        &path,
        Some(&admin_token),
        Some(&patch),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mails = f.deliver().await;
    let mail = only_to(&mails, "moved@example.com");
    assert!(
        mail.body.contains("/myaccount/verify-email#token="),
        "{}",
        mail.body
    );
    assert!(!mail.body.contains("/login/invite"), "{}", mail.body);
}

#[tokio::test]
async fn the_passkey_cap_is_enforced_before_creation_options() {
    let f = Fixture::new().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let mut auth = Authenticator::new(Alg::Es256, T);
    let first = register_ok(&f, &token, &mut auth).await;
    let template = webauthn_credentials::Entity::find()
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    for i in 1..MAX_PER_USER {
        let mut row: webauthn_credentials::ActiveModel = template.clone().into();
        row.id = Set(Uuid::now_v7());
        row.credential_id = Set(vec![u8::try_from(i).unwrap(); 16]);
        webauthn_credentials::Entity::insert(row)
            .exec_without_returning(&f.db)
            .await
            .unwrap();
    }
    let (status, body) = me_call(
        &f,
        &token,
        Method::POST,
        "/passkeys/options",
        Some(json!({ "password": PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    // One gone: options again.
    let path = format!("/passkeys/{}", first["id"].as_str().unwrap());
    let (status, _) = me_call(
        &f,
        &token,
        Method::DELETE,
        &path,
        Some(json!({ "password": PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = me_call(
        &f,
        &token,
        Method::POST,
        "/passkeys/options",
        Some(json!({ "password": PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
