//! Federation round-trip security: single-use, expiring, browser-bound
//! state; every ID token check; discovery / JWKS behaviour; client auth.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use common::{
    ORIGIN,
    browser::{Browser, query_of},
    federation::{Fed, follow, login_error},
    mgmt::audited_any,
    upstream::{CLIENT_ID, CLIENT_SECRET, Tweak},
};
use entity::federation_states;
use sea_orm::{EntityTrait, PaginatorTrait, sea_query::Expr};
use serde_json::json;

const EXPIRED: &str = "/login?error=upstream_failed";

/// Signs in with `tweak` active; returns the callback's redirect.
async fn with_tweak(fed: &Fed, idp: &str, tweak: Tweak) -> String {
    fed.up.tweak(tweak);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), idp).await;
    fed.up.tweak(Tweak::None);
    location
}

/// The reason code of the newest failed federated sign-in.
async fn last_reason(fed: &Fed) -> String {
    let events = audited_any(&fed.f.db, "sign_in").await;
    events.last().unwrap()["reason"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn every_id_token_check_holds() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let other = format!("{}/x", fed.up.issuer);
    let cases = [
        (Tweak::Issuer(other), "id_token_iss"),
        (Tweak::Audience(json!("someone-else")), "id_token_aud"),
        (Tweak::Audience(json!([CLIENT_ID, "other"])), "id_token_aud"),
        (Tweak::Azp("other".into()), "id_token_aud"),
        (Tweak::Nonce("forged".into()), "id_token_nonce"),
        (Tweak::ExpOffset(-120), "id_token_expired"),
        (Tweak::IatOffset(600), "id_token_iat"),
        (Tweak::WrongKey, "id_token_signature"),
        (Tweak::UnknownKid, "unknown_kid"),
        (Tweak::Hs256, "id_token_alg"),
        (Tweak::AlgNone, "id_token_malformed"),
        (Tweak::TokenError, "token_refused"),
    ];
    for (tweak, reason) in cases {
        let location = with_tweak(&fed, &idp, tweak.clone()).await;
        assert_eq!(
            login_error(&location).as_deref(),
            Some("upstream_failed"),
            "{tweak:?}"
        );
        assert_eq!(last_reason(&fed).await, reason, "{tweak:?}");
    }
    let location = with_tweak(&fed, &idp, Tweak::ExpOffset(-30)).await;
    assert!(location.starts_with(common::flow::WEB_CB), "{location}");
    assert!(
        directory_user(&fed).await,
        "a token within the 60 s skew signs in"
    );
}

async fn directory_user(fed: &Fed) -> bool {
    oauth_server::directory::find_user_by_email(&fed.f.db, fed.f.tenant.id, "pat@upstream.example")
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn state_is_single_use_browser_bound_and_expiring() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let mut browser = fed.f.browser();
    let tx = fed.authorize(&mut browser, &[]).await;
    let url = fed.begin(&mut browser, &tx, &idp).await;
    let callback = fed.up.authorize(&url);
    // Another browser (no binding cookie) can't use it, and burns it.
    let mut thief = Browser::new(fed.f.app.clone());
    assert_eq!(
        follow(&mut thief, &callback).await,
        format!("{ORIGIN}{EXPIRED}")
    );
    assert_eq!(
        follow(&mut browser, &callback).await,
        format!("{ORIGIN}{EXPIRED}")
    );
    assert!(!directory_user(&fed).await);
    // Replay of a used state.
    let url = fed.begin(&mut browser, &tx, &idp).await;
    let callback = fed.up.authorize(&url);
    let first = follow(&mut browser, &callback).await;
    assert!(first.starts_with(common::flow::WEB_CB), "{first}");
    assert_eq!(
        follow(&mut browser, &callback).await,
        format!("{ORIGIN}{EXPIRED}")
    );
    // An expired state.
    let mut browser = fed.f.browser();
    let tx = fed.authorize(&mut browser, &[]).await;
    let url = fed.begin(&mut browser, &tx, &idp).await;
    federation_states::Entity::update_many()
        .col_expr(
            federation_states::Column::ExpiresAt,
            Expr::cust("now() - interval '1 second'"),
        )
        .exec(&fed.f.db)
        .await
        .unwrap();
    assert_eq!(
        fed.come_back(&mut browser, &url).await,
        format!("{ORIGIN}{EXPIRED}")
    );
    // Unknown and missing states.
    let forged = format!("/federation/callback?code=x&state={}", "A".repeat(43));
    assert_eq!(
        follow(&mut browser, &forged).await,
        format!("{ORIGIN}{EXPIRED}")
    );
    assert_eq!(
        follow(&mut browser, "/federation/callback?code=x").await,
        format!("{ORIGIN}{EXPIRED}")
    );
}

#[tokio::test]
async fn one_live_state_per_transaction_and_it_carries_pkce() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let mut browser = fed.f.browser();
    let tx = fed.authorize(&mut browser, &[]).await;
    let first = fed.begin(&mut browser, &tx, &idp).await;
    let second = fed.begin(&mut browser, &tx, &idp).await;
    let rows = federation_states::Entity::find()
        .count(&fed.f.db)
        .await
        .unwrap();
    assert_eq!(rows, 1);
    let (a, b) = (query_of(&first), query_of(&second));
    assert_ne!(a["state"], b["state"]);
    assert_ne!(a["nonce"], b["nonce"]);
    assert_eq!(a["redirect_uri"], format!("{ORIGIN}/federation/callback"));
    // The replaced round trip is dead.
    assert_eq!(
        fed.come_back(&mut browser, &first).await,
        format!("{ORIGIN}{EXPIRED}")
    );
}

#[tokio::test]
async fn upstream_errors_and_mixups_fail_generically() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let mut browser = fed.f.browser();
    let tx = fed.authorize(&mut browser, &[]).await;
    // Discovery naming another issuer: refused before the browser leaves.
    let broken = fed.idp(json!({ "name": "Broken" })).await;
    fed.up.tweak(Tweak::DiscoveryIssuer);
    let (status, body) = browser
        .step(&tx, &format!("federation/{broken}"), json!({}))
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_GATEWAY, Some("upstream_failed"))
    );
    assert_eq!(last_reason(&fed).await, "discovery_issuer_mismatch");
    fed.up.tweak(Tweak::None);
    // The failure is remembered for a while (no refetch per attempt).
    let (status, _) = browser
        .step(&tx, &format!("federation/{broken}"), json!({}))
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let url = fed.begin(&mut browser, &tx, &idp).await;
    let state = query_of(&url)["state"].clone();
    let denied = format!("/federation/callback?error=access_denied&state={state}");
    let location = follow(&mut browser, &denied).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    assert_eq!(last_reason(&fed).await, "upstream_error");
    let url = fed.begin(&mut browser, &tx, &idp).await;
    let mixup = format!("{}&iss=https%3A%2F%2Fevil.example", fed.up.authorize(&url));
    let location = follow(&mut browser, &mixup).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    assert_eq!(last_reason(&fed).await, "iss_param");
}

#[tokio::test]
async fn client_auth_methods_and_jwks_refetch_limit() {
    let fed = Fed::new().await;
    let post = fed.idp(json!({ "name": "Post" })).await;
    let basic = fed
        .idp(json!({ "name": "Basic", "client_auth": "basic" }))
        .await;
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &post).await;
    assert!(location.starts_with(common::flow::WEB_CB), "{location}");
    fed.up
        .set_account(common::upstream::Account::new("s2", "b@upstream.example"));
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &basic).await;
    assert!(location.starts_with(common::flow::WEB_CB), "{location}");
    let auth = fed.up.token_auth();
    let secret = Some(CLIENT_SECRET.to_owned());
    assert_eq!(auth[0], (CLIENT_ID.to_owned(), secret.clone(), "post"));
    assert_eq!(auth[1], (CLIENT_ID.to_owned(), secret, "basic"));
    // Cached: the JWKS was fetched once for both sign-ins.
    assert_eq!(fed.up.jwks_fetches(), 1);
    // A rotation within the minute isn't picked up (bounded refetching) …
    fed.up.rotate().await;
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &post).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    assert_eq!(last_reason(&fed).await, "unknown_kid");
    assert_eq!(fed.up.jwks_fetches(), 1);
}
