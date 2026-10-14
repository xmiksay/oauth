// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Passkey sign-in: passwordless at the password step, second factor at
//! the MFA step, and every way an assertion must fail.
mod common;

use axum::http::StatusCode;
use common::{
    authenticator::{Alg, Authenticator, Tweak, UP, UV},
    browser::{Browser, authorize_url, query_of},
    flow::{Fixture, PASSWORD, T, WEB_CB},
    mgmt::{audited, mint_user_token},
    passkeys::{
        enrolled, last_failure, login_step, openid, refused, register_at, register_ok, sign_in,
    },
    seed::add_user,
};
use entity::users;
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use serde_json::{Value, json};

/// Exchanges the code of `redirect` and returns the ID token's `amr`.
async fn amr_of(f: &Fixture, redirect: &str) -> Value {
    let code = query_of(redirect).get("code").cloned().unwrap();
    let (status, tokens) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let claims = f
        .verify_jwt(tokens["id_token"].as_str().unwrap(), "web-app")
        .await;
    claims["amr"].clone()
}

#[tokio::test]
async fn register_then_passwordless_sign_in_skips_mfa_and_gets_tokens() {
    let f = Fixture::new().await;
    // TOTP and a forced password change are both skipped: a user-verifying
    // passkey is multi-factor by itself.
    f.enroll_totp(&f.user).await;
    let mut row: users::ActiveModel = f.user.clone().into();
    row.must_change_password = Set(true);
    row.update(&f.db).await.unwrap();
    let mut auth = enrolled(&f, Alg::Es256).await;

    let mut browser = f.browser();
    let tx = browser.authorize(&openid()).await.unwrap();
    let (_, _, view) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    let view: Value = serde_json::from_str(&view).unwrap();
    assert_eq!(view["factors"], json!(["password", "passkey"]));
    let (status, options) = browser.step(&tx, "passkey/options", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(options["publicKey"]["allowCredentials"], json!([]));
    assert_eq!(options["publicKey"]["rpId"], "contoso.id.example.test");
    assert_eq!(options["publicKey"]["userVerification"], "required");
    let (status, resp) = browser
        .step(&tx, "passkey", auth.get(&options, &Tweak::default()))
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(browser.has_session());
    let amr = amr_of(&f, resp["redirect"].as_str().unwrap()).await;
    assert_eq!(amr, json!(["hwk", "user", "mfa"]));
    let ok = audited(&f.db, "sign_in", f.user.id).await;
    assert_eq!(ok.last().unwrap()["amr"], json!(["hwk", "user", "mfa"]));
}

#[tokio::test]
async fn synced_passkeys_sign_in_as_swk_without_counters() {
    let f = Fixture::new().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let mut auth = Authenticator::synced(Alg::EdDsa, T);
    let created = register_ok(&f, &token, &mut auth).await;
    assert_eq!(
        (
            created["backup_eligible"].as_bool(),
            created["backup_state"].as_bool()
        ),
        (Some(true), Some(true))
    );
    for _ in 0..2 {
        let (status, resp) = sign_in(&f, &mut auth, &Tweak::default()).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let amr = amr_of(&f, resp["redirect"].as_str().unwrap()).await;
        assert_eq!(amr, json!(["swk", "user", "mfa"]));
    }
}

#[tokio::test]
async fn password_then_passkey_as_second_factor() {
    let f = Fixture::new().await;
    let mut auth = enrolled(&f, Alg::Rs256).await;
    let mut browser = f.browser();
    let tx = browser.authorize(&openid()).await.unwrap();
    let body = json!({ "email": "ann@example.com", "password": PASSWORD });
    let (status, view) = browser.step(&tx, "password", body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["step"], "mfa");
    assert_eq!(view["factors"], json!(["passkey"]));
    let (status, options) = browser.step(&tx, "passkey/options", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let allowed = options["publicKey"]["allowCredentials"].as_array().unwrap();
    assert_eq!(allowed.len(), 1);
    let (status, resp) = browser
        .step(&tx, "passkey", auth.get(&options, &Tweak::default()))
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let amr = amr_of(&f, resp["redirect"].as_str().unwrap()).await;
    assert_eq!(amr, json!(["pwd", "hwk", "mfa"]));
}

#[tokio::test]
async fn at_the_mfa_step_only_the_users_own_passkey_counts() {
    let f = Fixture::new().await;
    enrolled(&f, Alg::Es256).await;
    let bob = add_user(&f.db, f.tenant.id, "bob@example.com", false).await;
    let bob_token = mint_user_token(&f.db, &f.config, &f.tenant, &bob).await;
    let mut bobs = Authenticator::new(Alg::Es256, T);
    register_ok(&f, &bob_token, &mut bobs).await;

    let mut browser = f.browser();
    let tx = browser.authorize(&openid()).await.unwrap();
    let body = json!({ "email": "ann@example.com", "password": PASSWORD });
    browser.step(&tx, "password", body).await;
    let (status, resp) = login_step(&mut browser, &tx, &mut bobs, &Tweak::default()).await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_credentials"))
    );
    assert_eq!(
        last_failure(&f, &f.user).await["reason"],
        "foreign_credential"
    );
    assert!(!browser.has_session());
}

#[tokio::test]
async fn tampered_assertions_are_refused() {
    let f = Fixture::new().await;
    let mut auth = enrolled(&f, Alg::Es256).await;
    let origin = |o: &str| Tweak {
        origin: Some(o.into()),
        ..Tweak::default()
    };
    refused(
        &f,
        &mut auth,
        origin("https://evil.example"),
        "wrong_origin",
    )
    .await;
    refused(
        &f,
        &mut auth,
        origin("https://fabrikam.id.example.test"),
        "wrong_origin",
    )
    .await;
    let rp = Tweak {
        rp_id: Some("id.example.test".into()),
        ..Tweak::default()
    };
    refused(&f, &mut auth, rp, "wrong_rp_id").await;
    let no_uv = Tweak {
        flags: Some(UP),
        ..Tweak::default()
    };
    refused(&f, &mut auth, no_uv, "user_not_verified").await;
    let no_up = Tweak {
        flags: Some(UV),
        ..Tweak::default()
    };
    refused(&f, &mut auth, no_up, "user_not_present").await;
    let bad_sig = Tweak {
        corrupt_signature: true,
        ..Tweak::default()
    };
    refused(&f, &mut auth, bad_sig, "bad_signature").await;
    let create = Tweak {
        client_type: Some("webauthn.create"),
        ..Tweak::default()
    };
    refused(&f, &mut auth, create, "wrong_type").await;
    let framed = Tweak {
        cross_origin: true,
        ..Tweak::default()
    };
    refused(&f, &mut auth, framed, "cross_origin").await;
    let no_handle = Tweak {
        user_handle: Some(None),
        ..Tweak::default()
    };
    refused(&f, &mut auth, no_handle, "foreign_credential").await;
    let other_handle = Tweak {
        user_handle: Some(Some(vec![7; 32])),
        ..Tweak::default()
    };
    refused(&f, &mut auth, other_handle, "foreign_credential").await;
    // Still fine afterwards.
    let (status, _) = sign_in(&f, &mut auth, &Tweak::default()).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn unknown_foreign_tenant_and_disabled_users() {
    let f = Fixture::new().await;
    let mut auth = enrolled(&f, Alg::Es256).await;

    let mut stranger = Authenticator::new(Alg::Es256, T);
    stranger.user_handle = Some(vec![1; 32]);
    let (status, _) = sign_in(&f, &mut stranger, &Tweak::default()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A passkey registered on another tenant, presented on this one.
    let other = oauth_server::directory::create_tenant(
        &f.db,
        &f.config,
        oauth_server::directory::NewTenant {
            slug: "fabrikam",
            display_name: "Fabrikam",
        },
    )
    .await
    .unwrap();
    let fab_user = add_user(&f.db, other.id, "ann@example.com", false).await;
    let fab_token = mint_user_token(&f.db, &f.config, &other, &fab_user).await;
    let mut fab = Authenticator::new(Alg::Es256, "fabrikam");
    let reauth = json!({ "password": PASSWORD });
    let base = common::at("fabrikam", "");
    let (status, body) = register_at(
        &f.app,
        &base,
        &fab_token,
        &mut fab,
        reauth,
        &Tweak::default(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    fab.rp_id = auth.rp_id.clone();
    fab.origin = auth.origin.clone();
    let (status, _) = sign_in(&f, &mut fab, &Tweak::default()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(audited(&f.db, "sign_in", fab_user.id).await.is_empty());

    let mut row: users::ActiveModel = f.user.clone().into();
    row.disabled = Set(true);
    row.update(&f.db).await.unwrap();
    let (status, resp) = sign_in(&f, &mut auth, &Tweak::default()).await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("account_disabled"))
    );
}

#[tokio::test]
async fn passkey_steps_only_at_password_and_mfa() {
    let f = Fixture::new().await;
    let mut auth = enrolled(&f, Alg::Es256).await;
    // Consent-stage transactions don't take passkeys.
    let mut browser: Browser = f.browser();
    let url = authorize_url("web-app", WEB_CB, "openid api://orders/Orders.Read", &[]);
    let tx = browser.authorize(&url).await.unwrap();
    let (status, view) = login_step(&mut browser, &tx, &mut auth, &Tweak::default()).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["step"], "consent");
    assert_eq!(view["factors"], json!([]));
    let (status, resp) = browser.step(&tx, "passkey/options", json!({})).await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::CONFLICT, Some("wrong_step"))
    );
}
