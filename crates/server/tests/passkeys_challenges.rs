// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Passkey sign-in: challenge lifetime and scope, and the sign counter.
mod common;

use axum::http::StatusCode;
use common::{
    authenticator::{Alg, Tweak},
    flow::Fixture,
    mgmt::mint_user_token,
    passkeys::{enrolled, last_failure, login_step, openid, reauth_with, refused, sign_in},
};
use entity::webauthn_challenges;
use sea_orm::{ConnectionTrait, EntityTrait};
use serde_json::{Value, json};

#[tokio::test]
async fn challenges_are_single_use_scoped_and_expire() {
    let f = Fixture::new().await;
    let mut auth = enrolled(&f, Alg::Es256).await;
    let tweak = Tweak::default();

    // A failed attempt burns the challenge: a valid answer to it is too late.
    let mut browser = f.browser();
    let tx = browser.authorize(&openid()).await.unwrap();
    let (_, options) = browser.step(&tx, "passkey/options", json!({})).await;
    let bad = auth.get(
        &options,
        &Tweak {
            corrupt_signature: true,
            ..Tweak::default()
        },
    );
    assert_eq!(
        browser.step(&tx, "passkey", bad).await.0,
        StatusCode::UNAUTHORIZED
    );
    let good = auth.get(&options, &tweak);
    assert_eq!(
        browser.step(&tx, "passkey", good).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        last_failure(&f, &f.user).await["reason"],
        "invalid_challenge"
    );

    // A successful assertion replayed in another transaction.
    let tx = browser.authorize(&openid()).await.unwrap();
    let (_, options) = browser.step(&tx, "passkey/options", json!({})).await;
    let assertion = auth.get(&options, &tweak);
    assert_eq!(
        browser.step(&tx, "passkey", assertion.clone()).await.0,
        StatusCode::OK
    );
    let mut other = f.browser();
    let tx2 = other.authorize(&openid()).await.unwrap();
    other.step(&tx2, "passkey/options", json!({})).await;
    assert_eq!(
        other.step(&tx2, "passkey", assertion).await.0,
        StatusCode::UNAUTHORIZED
    );

    // Only the newest challenge of a transaction is live.
    let tx = other.authorize(&openid()).await.unwrap();
    let (_, first) = other.step(&tx, "passkey/options", json!({})).await;
    other.step(&tx, "passkey/options", json!({})).await;
    let stale = auth.get(&first, &tweak);
    assert_eq!(
        other.step(&tx, "passkey", stale).await.0,
        StatusCode::UNAUTHORIZED
    );

    // Expired.
    let tx = other.authorize(&openid()).await.unwrap();
    let (_, options) = other.step(&tx, "passkey/options", json!({})).await;
    f.db.execute_unprepared(
        "UPDATE webauthn_challenges SET expires_at = now() - interval '1 second'",
    )
    .await
    .unwrap();
    let late = auth.get(&options, &tweak);
    assert_eq!(
        other.step(&tx, "passkey", late).await.0,
        StatusCode::UNAUTHORIZED
    );

    // A challenge issued for another purpose (My Account re-auth).
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let reauth = reauth_with(&f, &token, &mut auth).await;
    let reauth_challenge = String::from_utf8(common::authenticator::unb64(
        reauth["passkey"]["response"]["clientDataJSON"]
            .as_str()
            .unwrap(),
    ))
    .unwrap();
    let challenge: Value = serde_json::from_str(&reauth_challenge).unwrap();
    let tx = other.authorize(&openid()).await.unwrap();
    other.step(&tx, "passkey/options", json!({})).await;
    let wrong_purpose = Tweak {
        challenge: Some(challenge["challenge"].as_str().unwrap().into()),
        ..Tweak::default()
    };
    let (status, _) = login_step(&mut other, &tx, &mut auth, &wrong_purpose).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        last_failure(&f, &f.user).await["reason"],
        "invalid_challenge"
    );
    // Answering with it at login did not consume the re-auth challenge.
    let left = webauthn_challenges::Entity::find()
        .all(&f.db)
        .await
        .unwrap();
    assert!(
        left.iter()
            .any(|c| c.purpose == entity::enums::WebauthnPurpose::Reauth),
        "{left:?}"
    );
}

#[tokio::test]
async fn a_sign_count_regression_is_refused_and_audited() {
    let f = Fixture::new().await;
    let mut auth = enrolled(&f, Alg::Es256).await;
    for _ in 0..2 {
        assert_eq!(
            sign_in(&f, &mut auth, &Tweak::default()).await.0,
            StatusCode::OK
        );
    }
    // The authenticator reported 2 last; a clone replays an older count.
    for count in [2, 1, 0] {
        let clone = Tweak {
            sign_count: Some(count),
            ..Tweak::default()
        };
        refused(&f, &mut auth, clone, "sign_count_regression").await;
    }
    let ahead = Tweak {
        sign_count: Some(10),
        ..Tweak::default()
    };
    assert_eq!(sign_in(&f, &mut auth, &ahead).await.0, StatusCode::OK);
}
