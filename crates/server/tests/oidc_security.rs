// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Browser binding of login transactions, security headers, malformed
//! input, schema rules and the authorize rate limit.
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{
    PUBLIC_URL,
    browser::{authorize_url, query_of, send},
    flow::{Fixture, PASSWORD, T, WEB_CB},
    seed::add_app,
};
use entity::enums::{AccessTokenFormat, ClientType, SigningAlg};
use serde_json::{Value, json};

#[tokio::test]
async fn login_transaction_is_bound_to_the_starting_browser() {
    let f = Fixture::new().await;
    let mut victim = f.browser();
    let tx = victim
        .authorize(&authorize_url(
            "web-app",
            WEB_CB,
            "openid api://orders/Orders.Read",
            &[],
        ))
        .await
        .unwrap();
    assert!(victim.cookies.contains_key("__Host-oauth_tx"));
    let creds = json!({ "email": "ann@example.com", "password": PASSWORD });

    // Another browser (no / a different binding cookie) can't see or drive it.
    let mut attacker = f.browser();
    assert_eq!(
        attacker.get(&format!("/{T}/api/authn/tx/{tx}")).await.0,
        StatusCode::NOT_FOUND
    );
    let (status, resp) = attacker.step(&tx, "password", creds.clone()).await;
    assert_eq!(
        (status, resp["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    attacker
        .cookies
        .insert("__Host-oauth_tx".into(), "x".repeat(43));
    assert_eq!(
        attacker.get(&format!("/{T}/api/authn/tx/{tx}")).await.0,
        StatusCode::NOT_FOUND
    );

    // The victim signs in; the attacker still can't approve consent for them.
    let (status, resp) = victim.step(&tx, "password", creds).await;
    assert_eq!(
        (status, resp["step"].as_str()),
        (StatusCode::OK, Some("consent"))
    );
    let approve = json!({ "approve": true, "scopes": ["Orders.Read"] });
    let (status, _) = attacker.step(&tx, "consent", approve.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!attacker.has_session());
    let (status, resp) = victim.step(&tx, "consent", approve).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(victim.has_session());
}

#[tokio::test]
async fn security_headers_on_every_route() {
    let f = Fixture::new().await;
    let authorize = authorize_url("web-app", WEB_CB, "openid", &[]);
    for path in [
        format!("/{T}/login"),
        authorize,
        format!("/{T}/api/authn/tx/x"),
        "/healthz".into(),
    ] {
        let (_, headers, _) = send(&f.app, Request::get(&path).body(Body::empty()).unwrap()).await;
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY", "{path}");
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'none'",
            "{path}"
        );
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer", "{path}");
    }
    let (_, headers, _) = f
        .post_form(&format!("/{T}/oauth2/token"), &[("grant_type", "x")], None)
        .await;
    assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
}

#[tokio::test]
async fn malformed_login_bodies_get_json_errors() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let tx = browser
        .authorize(&authorize_url("web-app", WEB_CB, "openid", &[]))
        .await
        .unwrap();
    let path = format!("/{T}/api/authn/tx/{tx}/password");
    for body in ["{not json", r#"{"email": "a@b.c"}"#, "[]"] {
        let req = Request::post(&path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, PUBLIC_URL)
            .body(Body::from(body))
            .unwrap();
        let (status, _, text) = browser.request(req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {text}");
        let json: Value = serde_json::from_str(&text).expect("JSON error body");
        assert_eq!(json["error"], "invalid_request");
    }
}

#[tokio::test]
async fn api_identifier_uri_must_name_the_apps_own_client_id() {
    let f = Fixture::new().await;
    let insert = |client_id: &'static str, uri: &'static str| {
        let f = &f;
        async move {
            use entity::applications;
            use sea_orm::{ActiveValue::Set, EntityTrait};
            applications::Entity::insert(applications::ActiveModel {
                id: Set(uuid::Uuid::now_v7()),
                tenant_id: Set(f.tenant.id),
                client_id: Set(client_id.into()),
                display_name: Set(client_id.into()),
                client_type: Set(ClientType::Confidential),
                identifier_uri: Set(Some(uri.into())),
                ..Default::default()
            })
            .exec_without_returning(&f.db)
            .await
        }
    };
    // `api://web-app` would make `api://web-app/...` name two apps.
    assert!(insert("squatter", "api://web-app").await.is_err());
    assert!(insert("squatter2", "API://web-app").await.is_err());
    assert!(insert("hr", "api://hr").await.is_ok());
    assert!(
        insert("billing", "https://billing.example/api")
            .await
            .is_ok()
    );
    let app = add_app(
        &f.db,
        f.tenant.id,
        "plain",
        ClientType::Confidential,
        None,
        AccessTokenFormat::Jwt,
        SigningAlg::Rs256,
    )
    .await;
    assert_eq!(oauth_server::oidc::scope::audience(&app), "api://plain");
}

#[tokio::test]
async fn authorize_is_rate_limited_per_ip() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let url = authorize_url("web-app", WEB_CB, "openid", &[]);
    for _ in 0..60 {
        browser.authorize(&url).await.unwrap();
    }
    let (status, _, body) = browser.get(&url).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["error"], "rate_limited");
    // Errors that need no transaction (e.g. prompt=none) are not limited.
    let none = authorize_url("web-app", WEB_CB, "openid", &[("prompt", "none")]);
    assert!(browser.authorize(&none).await.is_err());
}

#[tokio::test]
async fn parallel_sign_ins_in_two_tabs_both_complete() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let url = authorize_url("web-app", WEB_CB, "openid", &[]);
    let tab1 = browser.authorize(&url).await.unwrap();
    let tab2 = browser.authorize(&url).await.unwrap();
    let first = browser.complete_login(&tab1, "ann@example.com").await;
    assert!(first.starts_with(WEB_CB), "{first}");
    // Finishing tab 1 must not orphan tab 2.
    let second = browser.complete_login(&tab2, "ann@example.com").await;
    assert!(second.starts_with(WEB_CB), "{second}");
}

#[tokio::test]
async fn a_session_does_not_cross_tenants() {
    let f = Fixture::new().await;
    oauth_server::directory::create_tenant(
        &f.db,
        &f.config,
        oauth_server::directory::NewTenant {
            slug: "fabrikam",
            display_name: "Fabrikam",
        },
    )
    .await
    .unwrap();
    let (mut browser, _) = f.web_tokens("openid", "ann@example.com").await;
    let callback = format!("{PUBLIC_URL}/fabrikam/admin/callback");
    let url = authorize_url("admin-portal", &callback, "openid", &[("prompt", "none")]).replacen(
        "/contoso/",
        "/fabrikam/",
        1,
    );
    let redirect = browser.authorize(&url).await.unwrap_err();
    assert_eq!(query_of(&redirect)["error"], "login_required");
    // Even presenting contoso's session value under fabrikam's cookie name.
    let value = browser.cookies["__Host-oauth_sid_contoso"].clone();
    browser
        .cookies
        .insert("__Host-oauth_sid_fabrikam".into(), value);
    let redirect = browser.authorize(&url).await.unwrap_err();
    assert_eq!(query_of(&redirect)["error"], "login_required");
}
