// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Passkeys in My Account (registration, re-authentication, rename,
//! removal, last-method protection) and in the admin center.
mod common;

use axum::http::{Method, StatusCode};
use ciborium::Value as Cbor;
use common::{
    authenticator::{Alg, Authenticator, Tweak, UP, cose_map},
    flow::{Fixture, PASSWORD, T},
    mgmt::{audited, mint_user_token},
    passkeys::{drop_password, login_step, me_call, reauth_with, register, register_ok},
};
use entity::webauthn_credentials;
use sea_orm::{ConnectionTrait, EntityTrait};
use serde_json::{Value, json};

fn pw() -> Value {
    json!({ "password": PASSWORD })
}

#[tokio::test]
async fn every_algorithm_registers_and_is_listed_renamed_and_removed() {
    let f = Fixture::new().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    for alg in [Alg::Es256, Alg::EdDsa, Alg::Rs256] {
        let mut auth = Authenticator::new(alg, T);
        let created = register_ok(&f, &token, &mut auth).await;
        assert_eq!(created["name"], "Laptop");
        assert_eq!(created["transports"], json!(["internal", "hybrid"]));
        assert_eq!(created["aaguid"], "11111111-1111-1111-1111-111111111111");
    }
    let algs: Vec<i32> = webauthn_credentials::Entity::find()
        .all(&f.db)
        .await
        .unwrap()
        .iter()
        .map(|c| c.alg)
        .collect();
    assert_eq!(algs, vec![-7, -8, -257]);
    let (_, me) = me_call(&f, &token, Method::GET, "", None).await;
    assert_eq!(me["mfa"]["passkeys"], 3);
    let (status, list) = me_call(&f, &token, Method::GET, "/passkeys", None).await;
    assert_eq!(status, StatusCode::OK);
    let id = list["items"][0]["id"].as_str().unwrap().to_owned();

    let rename = Some(json!({ "name": "  Work key " }));
    let (status, renamed) = me_call(
        &f,
        &token,
        Method::PATCH,
        &format!("/passkeys/{id}"),
        rename,
    )
    .await;
    assert_eq!(
        (status, renamed["name"].as_str()),
        (StatusCode::OK, Some("Work key"))
    );
    let long = Some(json!({ "name": "x".repeat(65) }));
    let (status, _) = me_call(&f, &token, Method::PATCH, &format!("/passkeys/{id}"), long).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let path = format!("/passkeys/{id}");
    let (status, _) = me_call(
        &f,
        &token,
        Method::DELETE,
        &path,
        Some(json!({ "password": "wrong password!" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = me_call(&f, &token, Method::DELETE, &path, Some(pw())).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = me_call(&f, &token, Method::DELETE, &path, Some(pw())).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        audited(&f.db, "user.mfa.passkey_register", f.user.id)
            .await
            .len(),
        3
    );
    let renames = audited(&f.db, "user.mfa.passkey_rename", f.user.id).await;
    assert_eq!(renames.len(), 1);
    assert_eq!(
        (renames[0]["name"].as_str(), renames[0]["via"].as_str()),
        (Some("Work key"), Some("me"))
    );
    let removed = audited(&f.db, "user.mfa.passkey_remove", f.user.id).await;
    assert_eq!(removed[0]["name"], "Work key");
}

#[tokio::test]
async fn registration_requires_reauth_and_a_valid_credential() {
    let f = Fixture::new().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let mut auth = Authenticator::new(Alg::Es256, T);
    let none = Tweak::default();
    for (reauth, expected) in [
        (json!({}), StatusCode::BAD_REQUEST),
        (
            json!({ "password": "wrong password!" }),
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(
            register(&f, &token, &mut auth, reauth, &none).await.0,
            expected
        );
    }
    let bad = |tweak: Tweak| tweak;
    let rsa_1024 = cose_map(vec![
        (1, Cbor::Integer(3.into())),
        (3, Cbor::Integer((-257).into())),
        (-1, Cbor::Bytes(vec![0xc5; 128])),
        (-2, Cbor::Bytes(vec![1, 0, 1])),
    ]);
    let es384 = cose_map(vec![
        (1, Cbor::Integer(2.into())),
        (3, Cbor::Integer((-35).into())),
        (-1, Cbor::Integer(2.into())),
        (-2, Cbor::Bytes(vec![1; 48])),
        (-3, Cbor::Bytes(vec![2; 48])),
    ]);
    for tweak in [
        bad(Tweak {
            origin: Some("https://evil.example".into()),
            ..Tweak::default()
        }),
        bad(Tweak {
            rp_id: Some("example.test".into()),
            ..Tweak::default()
        }),
        bad(Tweak {
            flags: Some(UP | 0x40),
            ..Tweak::default()
        }),
        bad(Tweak {
            client_type: Some("webauthn.get"),
            ..Tweak::default()
        }),
        bad(Tweak {
            cose_key: Some(rsa_1024),
            ..Tweak::default()
        }),
        bad(Tweak {
            cose_key: Some(es384),
            ..Tweak::default()
        }),
        bad(Tweak {
            challenge: Some("bm90IHRoZSBjaGFsbGVuZ2U".into()),
            ..Tweak::default()
        }),
    ] {
        let (status, body) = register(&f, &token, &mut auth, pw(), &tweak).await;
        assert_eq!(
            (status, body["error_description"].as_str()),
            (
                StatusCode::BAD_REQUEST,
                Some("the passkey could not be registered")
            )
        );
    }
    assert!(
        webauthn_credentials::Entity::find()
            .all(&f.db)
            .await
            .unwrap()
            .is_empty()
    );

    // A registration response is single use; a known credential is a 409.
    let (_, options) = me_call(&f, &token, Method::POST, "/passkeys/options", Some(pw())).await;
    let credential = auth.create(&options, &none);
    let body = Some(json!({ "credential": credential }));
    let (status, created) = me_call(&f, &token, Method::POST, "/passkeys", body.clone()).await;
    assert_eq!(
        (status, created["name"].as_str()),
        (StatusCode::CREATED, Some("Passkey"))
    );
    assert_eq!(
        me_call(&f, &token, Method::POST, "/passkeys", body).await.0,
        StatusCode::BAD_REQUEST
    );
    // (Many password checks so far: start a fresh rate-limit window.)
    f.db.execute_unprepared("DELETE FROM rate_limit_buckets")
        .await
        .unwrap();
    let (status, _) = register(&f, &token, &mut auth, pw(), &none).await;
    assert_eq!(status, StatusCode::CONFLICT);
    // The creation options exclude what is registered.
    let (_, options) = me_call(&f, &token, Method::POST, "/passkeys/options", Some(pw())).await;
    assert_eq!(
        options["publicKey"]["excludeCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(options["publicKey"]["attestation"], "none");
    assert_eq!(
        options["publicKey"]["authenticatorSelection"]["residentKey"],
        "required"
    );
}

#[tokio::test]
async fn a_passkey_only_user_manages_the_account_with_passkeys() {
    let f = Fixture::new().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let mut first = Authenticator::new(Alg::Es256, T);
    let first_id = register_ok(&f, &token, &mut first).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let user = drop_password(&f, &f.user).await;
    assert!(user.password_hash.is_none());
    assert_eq!(
        register(
            &f,
            &token,
            &mut Authenticator::new(Alg::Es256, T),
            pw(),
            &Tweak::default()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );

    // Last sign-in method: can't go.
    let reauth = reauth_with(&f, &token, &mut first).await;
    let path = format!("/passkeys/{first_id}");
    let (status, body) = me_call(&f, &token, Method::DELETE, &path, Some(reauth)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // A second one, re-authenticated by the first.
    let mut second = Authenticator::synced(Alg::EdDsa, T);
    let reauth = reauth_with(&f, &token, &mut first).await;
    let (status, created) = register(&f, &token, &mut second, reauth, &Tweak::default()).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    // A re-auth assertion works once, and only for this user's passkeys.
    let reauth = reauth_with(&f, &token, &mut second).await;
    let (status, _) = me_call(&f, &token, Method::DELETE, &path, Some(reauth.clone())).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let second_id = created["id"].as_str().unwrap();
    let path = format!("/passkeys/{second_id}");
    assert_eq!(
        me_call(&f, &token, Method::DELETE, &path, Some(reauth))
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    // Setting a first password through passkey re-auth, then the last
    // passkey may go.
    let reauth = reauth_with(&f, &token, &mut second).await;
    let mut body = reauth.clone();
    body["new_password"] = json!("a brand new passphrase");
    let (status, resp) = me_call(&f, &token, Method::POST, "/change-password", Some(body)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{resp}");
    let reauth = json!({ "password": "a brand new passphrase" });
    assert_eq!(
        me_call(&f, &token, Method::DELETE, &path, Some(reauth))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let (status, _) = me_call(&f, &token, Method::POST, "/reauth/options", Some(json!({}))).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn reauth_rejects_foreign_cloned_and_wrong_purpose_assertions() {
    let f = Fixture::new().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let mut mine = Authenticator::new(Alg::Es256, T);
    register_ok(&f, &token, &mut mine).await;
    let bob = common::seed::add_user(&f.db, f.tenant.id, "bob@example.com", false).await;
    let bob_token = mint_user_token(&f.db, &f.config, &f.tenant, &bob).await;
    let mut bobs = Authenticator::new(Alg::Es256, T);
    register_ok(&f, &bob_token, &mut bobs).await;
    let begin = |reauth: Value| async {
        me_call(&f, &token, Method::POST, "/passkeys/options", Some(reauth))
            .await
            .0
    };
    // Bob's passkey answering Ann's challenge.
    let (_, options) = me_call(&f, &token, Method::POST, "/reauth/options", Some(json!({}))).await;
    let foreign = json!({ "passkey": bobs.get(&options, &Tweak::default()) });
    assert_eq!(begin(foreign).await, StatusCode::FORBIDDEN);
    // A login challenge isn't a re-auth challenge.
    let mut browser = f.browser();
    let tx = browser
        .authorize(&common::browser::authorize_url(
            "web-app",
            common::flow::WEB_CB,
            "openid",
            &[],
        ))
        .await
        .unwrap();
    let (_, login_options) = browser.step(&tx, "passkey/options", json!({})).await;
    let wrong = json!({ "passkey": mine.get(&login_options, &Tweak::default()) });
    assert_eq!(begin(wrong).await, StatusCode::FORBIDDEN);
    // A clone: counter not advancing past the last accepted one (2).
    assert_eq!(
        begin(reauth_with(&f, &token, &mut mine).await).await,
        StatusCode::OK
    );
    let (_, options) = me_call(&f, &token, Method::POST, "/reauth/options", Some(json!({}))).await;
    let clone = json!({ "passkey": mine.get(&options, &Tweak { sign_count: Some(0), ..Tweak::default() }) });
    assert_eq!(begin(clone).await, StatusCode::FORBIDDEN);
    let alarms = audited(&f.db, "user.mfa.passkey_sign_count_regression", f.user.id).await;
    assert_eq!(alarms, vec![json!({ "via": "reauth" })]);
    // Both proofs at once: 400.
    let mut both = reauth_with(&f, &token, &mut mine).await;
    both["password"] = json!(PASSWORD);
    assert_eq!(begin(both).await, StatusCode::BAD_REQUEST);
    assert_eq!(
        begin(reauth_with(&f, &token, &mut mine).await).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn passkey_attempts_are_rate_limited_per_account() {
    let f = Fixture::new().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let mut auth = Authenticator::new(Alg::Es256, T);
    register_ok(&f, &token, &mut auth).await;
    f.db.execute_unprepared("DELETE FROM rate_limit_buckets")
        .await
        .unwrap();
    let url = common::browser::authorize_url("web-app", common::flow::WEB_CB, "openid", &[]);
    let bad = Tweak {
        corrupt_signature: true,
        ..Tweak::default()
    };
    let mut statuses = Vec::new();
    for _ in 0..11 {
        let mut browser = f.browser();
        let tx = browser.authorize(&url).await.unwrap();
        statuses.push(login_step(&mut browser, &tx, &mut auth, &bad).await.0);
    }
    assert_eq!(statuses[..10], [StatusCode::UNAUTHORIZED; 10]);
    assert_eq!(statuses[10], StatusCode::TOO_MANY_REQUESTS);
}
