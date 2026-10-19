//! Federated sign-in: the first-sign-in policies, never linking by email,
//! disabled users, profile sync and local MFA vs trusted upstream MFA.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use common::{
    browser::current_totp,
    federation::{Fed, is_login_page, login_error},
    flow::PASSWORD,
    mgmt::audited,
    upstream::Account,
};
use entity::{user_identities, users};
use oauth_server::directory;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde_json::{Value, json};

async fn identities_of(fed: &Fed, user_id: uuid::Uuid) -> Vec<user_identities::Model> {
    user_identities::Entity::find()
        .filter(user_identities::Column::UserId.eq(user_id))
        .all(&fed.f.db)
        .await
        .unwrap()
}

async fn user_by_email(fed: &Fed, email: &str) -> Option<users::Model> {
    directory::find_user_by_email(&fed.f.db, fed.f.tenant.id, email)
        .await
        .unwrap()
}

async fn view(browser: &mut common::browser::Browser, tx: &str) -> Value {
    let (status, _, body) = browser.get(&format!("/api/authn/tx/{tx}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_str(&body).unwrap()
}

#[tokio::test]
async fn jit_creates_a_verified_user_once() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let mut browser = fed.f.browser();
    let (_, location) = fed.sign_in(&mut browser, &idp).await;
    assert_eq!(fed.amr(&location).await, ["fed"]);
    let user = user_by_email(&fed, "pat@upstream.example").await.unwrap();
    assert!(user.email_verified && user.password_hash.is_none());
    assert_eq!(user.display_name, "Upstream Person");
    let linked = identities_of(&fed, user.id).await;
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].subject, "upstream-sub-1");
    let created = audited(&fed.f.db, "user.create", user.id).await;
    assert_eq!(created[0]["via"], "federation");
    // The second time it signs the same user in.
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(fed.amr(&location).await, ["fed"]);
    assert_eq!(identities_of(&fed, user.id).await.len(), 1);
}

#[tokio::test]
async fn jit_never_links_by_email_and_needs_a_verified_one() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    // The fixture user's address, verified upstream: still no automatic link.
    fed.up
        .set_account(Account::new("other-sub", "ANN@example.com"));
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(login_error(&location).as_deref(), Some("account_exists"));
    assert!(identities_of(&fed, fed.f.user.id).await.is_empty());
    let mut unverified = Account::new("u2", "new@upstream.example");
    unverified.email_verified = false;
    fed.up.set_account(unverified);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_no_email"));
    let mut no_email = Account::new("u3", "x@upstream.example");
    no_email.email = None;
    fed.up.set_account(no_email);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_no_email"));
    assert!(user_by_email(&fed, "new@upstream.example").await.is_none());
}

#[tokio::test]
async fn link_only_links_after_a_local_sign_in_with_mfa() {
    let fed = Fed::new().await;
    fed.f.enroll_totp(&fed.f.user).await;
    let idp = fed
        .idp(json!({ "policy": "link_only", "name": "Contoso SSO" }))
        .await;
    let mut browser = fed.f.browser();
    let (tx, location) = fed.sign_in(&mut browser, &idp).await;
    assert!(is_login_page(&location, &tx), "{location}");
    let step = view(&mut browser, &tx).await;
    assert_eq!(step["step"], "link");
    assert_eq!(step["link"]["idp"]["name"], "Contoso SSO");
    assert_eq!(step["link"]["email"], "pat@upstream.example");
    assert_eq!(step["factors"], json!(["password", "passkey"]));
    // Federation itself is not offered again at this stage.
    let (status, _) = browser
        .step(&tx, &format!("federation/{idp}"), json!({}))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let body = json!({ "email": "ann@example.com", "password": PASSWORD });
    let (status, resp) = browser.step(&tx, "password", body).await;
    assert_eq!(
        (status, resp["step"].as_str()),
        (StatusCode::OK, Some("mfa"))
    );
    assert!(identities_of(&fed, fed.f.user.id).await.is_empty());
    let (status, resp) = browser
        .step(&tx, "totp", json!({ "code": current_totp() }))
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        fed.amr(resp["redirect"].as_str().unwrap()).await,
        ["pwd", "otp", "mfa"]
    );
    let linked = identities_of(&fed, fed.f.user.id).await;
    assert_eq!(linked.len(), 1);
    let events = audited(&fed.f.db, "user.identity_link", fed.f.user.id).await;
    assert_eq!(events[0]["via"], "sign_in");
    // Linked now: the next federated sign-in needs only the local MFA.
    let mut browser = fed.f.browser();
    let (tx, location) = fed.sign_in(&mut browser, &idp).await;
    assert!(is_login_page(&location, &tx));
    assert_eq!(view(&mut browser, &tx).await["step"], "mfa");
    // The code was just used (replay protection); forget that for the test.
    entity::user_totp::Entity::update_many()
        .col_expr(
            entity::user_totp::Column::LastUsedStep,
            sea_orm::sea_query::Expr::value(Option::<i64>::None),
        )
        .exec(&fed.f.db)
        .await
        .unwrap();
    let (_, resp) = browser
        .step(&tx, "totp", json!({ "code": current_totp() }))
        .await;
    assert_eq!(
        fed.amr(resp["redirect"].as_str().unwrap()).await,
        ["fed", "otp", "mfa"]
    );
}

#[tokio::test]
async fn trusted_upstream_mfa_replaces_the_local_factor() {
    let fed = Fed::new().await;
    fed.f.enroll_totp(&fed.f.user).await;
    let idp = fed.idp(json!({ "policy": "link_only" })).await;
    let mut browser = fed.f.browser();
    let (tx, _) = fed.sign_in(&mut browser, &idp).await;
    let body = json!({ "email": "ann@example.com", "password": PASSWORD });
    browser.step(&tx, "password", body).await;
    let (_, resp) = browser
        .step(&tx, "totp", json!({ "code": current_totp() }))
        .await;
    assert!(resp["redirect"].is_string(), "{resp}");
    let mut account = Account::new("upstream-sub-1", "pat@upstream.example");
    account.amr = vec!["pwd".into(), "mfa".into()];
    fed.up.set_account(account.clone());
    // Not trusted (the default): the upstream's MFA doesn't count.
    let mut browser = fed.f.browser();
    let (tx, location) = fed.sign_in(&mut browser, &idp).await;
    assert!(is_login_page(&location, &tx));
    assert_eq!(view(&mut browser, &tx).await["step"], "mfa");
    fed.patch_idp(&idp, json!({ "trust_upstream_mfa": true }))
        .await;
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(fed.amr(&location).await, ["fed", "mfa"]);
    // Trusted, but this sign-in upstream was single-factor.
    account.amr = vec!["pwd".into()];
    account.acr = Some("urn:strong".into());
    fed.up.set_account(account);
    let (tx, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert!(is_login_page(&location, &tx));
    // … unless its `acr` is the configured MFA value.
    fed.patch_idp(&idp, json!({ "mfa_acr": "urn:strong" }))
        .await;
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(fed.amr(&location).await, ["fed", "mfa"]);
}

#[tokio::test]
async fn deny_and_disabled_users_are_refused() {
    let fed = Fed::new().await;
    let deny = fed.idp(json!({ "policy": "deny", "name": "Strict" })).await;
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &deny).await;
    assert_eq!(login_error(&location).as_deref(), Some("not_linked"));
    let jit = fed.idp(json!({ "name": "Open" })).await;
    fed.sign_in(&mut fed.f.browser(), &jit).await;
    let user = user_by_email(&fed, "pat@upstream.example").await.unwrap();
    let mut row: users::ActiveModel = user.clone().into();
    row.disabled = Set(true);
    row.update(&fed.f.db).await.unwrap();
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &jit).await;
    assert_eq!(login_error(&location).as_deref(), Some("account_disabled"));
    let failures = audited(&fed.f.db, "sign_in", user.id).await;
    assert_eq!(failures.last().unwrap()["reason"], "account_disabled");
}

#[tokio::test]
async fn profile_sync_updates_the_name_never_the_email() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    fed.sign_in(&mut fed.f.browser(), &idp).await;
    let mut account = Account::new("upstream-sub-1", "renamed@upstream.example");
    account.name = Some("Pat Renamed".into());
    fed.up.set_account(account);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    fed.amr(&location).await;
    let user = user_by_email(&fed, "pat@upstream.example").await.unwrap();
    assert_eq!(user.display_name, "Pat Renamed");
    assert!(
        user_by_email(&fed, "renamed@upstream.example")
            .await
            .is_none()
    );
    let linked = identities_of(&fed, user.id).await;
    assert_eq!(linked[0].email.as_deref(), Some("renamed@upstream.example"));
    let updates = audited(&fed.f.db, "user.profile_update", user.id).await;
    assert_eq!(updates[0]["fields"], json!(["display_name"]));
}

#[tokio::test]
async fn login_page_offers_providers_and_honours_hints() {
    let fed = Fed::new().await;
    let shown = fed
        .idp(json!({ "email_domains": ["upstream.example"] }))
        .await;
    let hidden = fed
        .idp(json!({ "name": "Hidden", "visible": false, "email_domains": ["corp.example"] }))
        .await;
    let off = fed.idp(json!({ "name": "Off", "enabled": false })).await;
    let mut browser = fed.f.browser();
    let tx = fed.authorize(&mut browser, &[]).await;
    let step = view(&mut browser, &tx).await;
    assert_eq!(step["idps"], json!([{ "id": shown, "name": "Upstream" }]));
    assert_eq!(step["features"]["federation"], true);
    assert!(step["idp_hint"].is_null());
    let tx = fed
        .authorize(&mut browser, &[("domain_hint", "Corp.Example")])
        .await;
    assert_eq!(view(&mut browser, &tx).await["idp_hint"]["id"], hidden);
    let tx = fed.authorize(&mut browser, &[("idp", &shown)]).await;
    assert_eq!(view(&mut browser, &tx).await["idp_hint"]["id"], shown);
    let tx = fed.authorize(&mut browser, &[("idp", &off)]).await;
    assert!(view(&mut browser, &tx).await["idp_hint"].is_null());
    let (status, _) = browser
        .step(&tx, &format!("federation/{off}"), json!({}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Home-realm discovery maps domains only.
    for (email, want) in [
        (
            "someone@corp.example",
            json!({ "idp": { "id": hidden, "name": "Hidden" } }),
        ),
        ("ann@example.com", json!({})),
        ("not-an-email", json!({})),
    ] {
        let (status, body) = browser
            .step(&tx, "discover", json!({ "email": email }))
            .await;
        assert_eq!((status, body), (StatusCode::OK, want), "{email}");
    }
    let mut last = StatusCode::OK;
    for _ in 0..30 {
        last = browser
            .step(&tx, "discover", json!({ "email": "a@corp.example" }))
            .await
            .0;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_provider_disabled_mid_flight_fails_closed() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let mut browser = fed.f.browser();
    let tx = fed.authorize(&mut browser, &[]).await;
    let url = fed.begin(&mut browser, &tx, &idp).await;
    fed.patch_idp(&idp, json!({ "enabled": false })).await;
    let location = fed.come_back(&mut browser, &url).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    assert!(user_by_email(&fed, "pat@upstream.example").await.is_none());
}
