//! Federation hardening: repointing a provider unlinks it, re-authentication
//! demands reach the provider and bind its `auth_time`, the last-method rule
//! ignores disabled providers, JIT domain limits, bounded profile claims and
//! rate limits.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::{Method, StatusCode};
use common::{
    federation::{Fed, code_of, login_error},
    flow::Fixture,
    mgmt::{audited_any, call},
    seed::insert,
    upstream::Account,
};
use entity::{users, webauthn_credentials};
use oauth_server::directory;
use sea_orm::ActiveValue::Set;
use serde_json::json;
use uuid::Uuid;

async fn jit_user(fed: &Fed, email: &str) -> users::Model {
    directory::find_user_by_email(&fed.f.db, fed.f.tenant.id, email)
        .await
        .unwrap()
        .unwrap()
}

async fn last_reason(fed: &Fed) -> String {
    let events = audited_any(&fed.f.db, "sign_in").await;
    events.last().unwrap()["reason"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn reauthentication_demands_reach_the_provider() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let attempt = |extra: &'static [(&'static str, &'static str)], auth_time: Option<i64>| {
        let fed = &fed;
        let idp = idp.clone();
        async move {
            let mut account = Account::new("upstream-sub-1", "pat@upstream.example");
            account.auth_time = auth_time;
            fed.up.set_account(account);
            let mut browser = fed.f.browser();
            let tx = fed.authorize(&mut browser, extra).await;
            let url = fed.begin(&mut browser, &tx, &idp).await;
            fed.come_back(&mut browser, &url).await
        }
    };
    let login: &[(&str, &str)] = &[("prompt", "login")];
    let location = attempt(login, None).await;
    assert_eq!(fed.up.last_authorize()["prompt"], "login");
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    assert_eq!(last_reason(&fed).await, "id_token_auth_time");
    let location = attempt(login, Some(-3600)).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    let location = attempt(login, Some(0)).await;
    code_of(&location);
    let aged: &[(&str, &str)] = &[("max_age", "600")];
    let location = attempt(aged, Some(-1000)).await;
    assert_eq!(fed.up.last_authorize()["max_age"], "600");
    assert!(!fed.up.last_authorize().contains_key("prompt"));
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    // Within max_age: our session's auth_time is the upstream one.
    let location = attempt(aged, Some(-300)).await;
    let code = code_of(&location);
    let (_, tokens) = fed
        .f
        .redeem(
            &fed.f.web,
            Some(&fed.f.web_secret),
            &code,
            common::flow::WEB_CB,
        )
        .await;
    let claims = fed
        .f
        .verify_jwt(tokens["id_token"].as_str().unwrap(), "web-app")
        .await;
    let age = chrono::Utc::now().timestamp() - claims["auth_time"].as_i64().unwrap();
    assert!((295..=310).contains(&age), "{age}");
    // Without a demand nothing is forwarded or required.
    let location = attempt(&[], None).await;
    code_of(&location);
    assert!(!fed.up.last_authorize().contains_key("max_age"));
}

async fn add_passkey(fed: &Fed, user: &users::Model) -> Uuid {
    let id = Uuid::now_v7();
    insert(
        &fed.f.db,
        webauthn_credentials::ActiveModel {
            id: Set(id),
            tenant_id: Set(user.tenant_id),
            user_id: Set(user.id),
            credential_id: Set(id.as_bytes().to_vec()),
            public_key: Set(vec![1, 2, 3]),
            alg: Set(-7),
            sign_count: Set(0),
            rp_id: Set("contoso.id.example.test".into()),
            transports: Set(vec![]),
            aaguid: Set(Uuid::nil()),
            name: Set("Key".into()),
            backup_eligible: Set(false),
            backup_state: Set(false),
            created_at: Set(chrono::Utc::now().fixed_offset()),
            last_used_at: Set(None),
        },
    )
    .await;
    id
}

#[tokio::test]
async fn only_identities_at_enabled_providers_count_as_a_way_in() {
    let fed = Fed::with(Fixture::with_email().await).await;
    let idp = fed.idp(json!({})).await;
    fed.sign_in(&mut fed.f.browser(), &idp).await;
    let user = jit_user(&fed, "pat@upstream.example").await;
    let app = &fed.f.app;
    let base = format!("/api/v1/users/{}", user.id);
    let admin = Some(fed.admin.as_str());
    // Enabled provider: the identity is a way in, the passkey may go.
    let key = add_passkey(&fed, &user).await;
    let (status, _) = call(
        app,
        Method::DELETE,
        &format!("{base}/passkeys/{key}"),
        admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(app, Method::POST, &format!("{base}/invite"), admin, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Disabled provider: it isn't.
    let key = add_passkey(&fed, &user).await;
    fed.patch_idp(&idp, json!({ "enabled": false })).await;
    let (status, _) = call(
        app,
        Method::DELETE,
        &format!("{base}/passkeys/{key}"),
        admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = call(app, Method::POST, &format!("{base}/reset-mfa"), admin, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    fed.patch_idp(&idp, json!({ "enabled": true })).await;
    let (status, _) = call(app, Method::POST, &format!("{base}/reset-mfa"), admin, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // No passkey left and the only identity at a disabled IdP: invitable.
    fed.patch_idp(&idp, json!({ "enabled": false })).await;
    let (status, _) = call(app, Method::POST, &format!("{base}/invite"), admin, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn jit_respects_domains_and_bounds_profile_claims() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({ "email_domains": ["corp.example"] })).await;
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(
        login_error(&location).as_deref(),
        Some("email_domain_not_allowed")
    );
    let mut account = Account::new("s-corp", "kim@Corp.Example");
    account.name = Some(format!("Kim\u{0} {}", "x".repeat(1000)));
    fed.up.set_account(account);
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    code_of(&location);
    let kim = jit_user(&fed, "kim@corp.example").await;
    assert!(!kim.display_name.contains('\u{0}'));
    assert_eq!(kim.display_name.chars().count(), 256);
    // An address the directory can't take: a generic failure, audited.
    fed.up
        .set_account(Account::new("s-odd", "odd name@corp.example"));
    let (_, location) = fed.sign_in(&mut fed.f.browser(), &idp).await;
    assert_eq!(login_error(&location).as_deref(), Some("upstream_failed"));
    assert_eq!(last_reason(&fed).await, "jit_invalid_email");
}

#[tokio::test]
async fn starting_upstream_sign_ins_is_rate_limited() {
    let fed = Fed::new().await;
    let idp = fed.idp(json!({})).await;
    let mut browser = fed.f.browser();
    let tx = fed.authorize(&mut browser, &[]).await;
    let mut statuses: Vec<StatusCode> = Vec::new();
    for _ in 0..31 {
        statuses.push(
            browser
                .step(&tx, &format!("federation/{idp}"), json!({}))
                .await
                .0,
        );
    }
    assert!(statuses[..30].iter().all(|s| *s == StatusCode::OK));
    assert_eq!(statuses[30], StatusCode::TOO_MANY_REQUESTS);
}
