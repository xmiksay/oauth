// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Token endpoint grants, refresh rotation, code replay, opaque tokens,
//! introspection and revocation.
mod common;

use axum::http::StatusCode;
use common::{
    browser::authorize_url,
    flow::{Fixture, WEB_CB},
    seed::{add_role, assign_role},
};
use serde_json::{Value, json};

const TOKEN: &str = "/contoso/oauth2/token";

async fn refresh(f: &Fixture, token: &str, scope: Option<&str>) -> (StatusCode, Value) {
    let mut form = vec![("grant_type", "refresh_token"), ("refresh_token", token)];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }
    let basic = Some(("web-app", f.web_secret.as_str()));
    let (status, _, body) = f.post_form(TOKEN, &form, basic).await;
    (status, body)
}

async fn web_tokens(f: &Fixture, scope: &str) -> Value {
    let mut browser = f.browser();
    let code = browser
        .login_for_code(
            &authorize_url("web-app", WEB_CB, scope, &[]),
            "ann@example.com",
        )
        .await;
    let (status, tokens) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    tokens
}

#[tokio::test]
async fn refresh_rotation_and_reuse_revokes_family() {
    let f = Fixture::new().await;
    let tokens = web_tokens(&f, "openid offline_access api://orders/Orders.Read").await;
    let rt1 = tokens["refresh_token"].as_str().unwrap().to_owned();

    // Down-scoping: only the access token narrows; scope can't grow.
    let (status, body) = refresh(&f, &rt1, Some("openid email")).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_scope"))
    );
    let (status, t2) = refresh(&f, &rt1, Some("api://orders/Orders.Read")).await;
    assert_eq!(status, StatusCode::OK, "{t2}");
    assert_eq!(t2["scope"], "api://orders/Orders.Read");
    assert!(
        t2.get("id_token").is_none(),
        "openid not in the narrowed scope"
    );
    let at = f
        .verify_jwt(t2["access_token"].as_str().unwrap(), "api://orders")
        .await;
    assert_eq!(at["scp"], "Orders.Read");
    let rt2 = t2["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(rt1, rt2);

    let (status, t3) = refresh(&f, &rt2, None).await;
    assert_eq!(status, StatusCode::OK, "{t3}");
    assert!(
        t3["id_token"].is_string(),
        "full scope again includes openid"
    );
    let rt3 = t3["refresh_token"].as_str().unwrap().to_owned();

    // Replaying rt1 (already rotated) kills the whole family, incl. rt3.
    let (status, body) = refresh(&f, &rt1, None).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    let (status, body) = refresh(&f, &rt3, None).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    assert_eq!(body["error_description"], "refresh token revoked");

    // Another client can't use someone else's refresh token.
    let tokens = web_tokens(&f, "openid offline_access").await;
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
        ("client_id", "spa-app"),
    ];
    let (status, _, body) = f.post_form(TOKEN, &form, None).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
}

#[tokio::test]
async fn code_replay_is_rejected_and_revokes_issued_tokens() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let url = authorize_url(
        "web-app",
        WEB_CB,
        "offline_access api://ledger/Ledger.Read",
        &[],
    );
    let code = browser.login_for_code(&url, "ann@example.com").await;
    let (status, tokens) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let (status, body) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );

    let (status, body) = refresh(&f, tokens["refresh_token"].as_str().unwrap(), None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "refresh token of a replayed code: {body}"
    );
    let introspect = [("token", tokens["access_token"].as_str().unwrap())];
    let basic = Some(("ledger", f.ledger_secret.as_str()));
    let (_, _, body) = f
        .post_form("/contoso/oauth2/introspect", &introspect, basic)
        .await;
    assert_eq!(
        body,
        json!({ "active": false }),
        "opaque token of a replayed code"
    );
}

#[tokio::test]
async fn opaque_tokens_introspection_and_revocation() {
    let f = Fixture::new().await;
    let tokens = web_tokens(&f, "offline_access api://ledger/Ledger.Read").await;
    let access = tokens["access_token"].as_str().unwrap();
    let refresh_token = tokens["refresh_token"].as_str().unwrap();
    assert!(!access.contains('.'), "ledger issues opaque tokens");
    assert!(tokens.get("id_token").is_none());

    let ask = |token: String, client: &'static str, secret: String| {
        let f = &f;
        async move {
            let (status, headers, body) = f
                .post_form(
                    "/contoso/oauth2/introspect",
                    &[("token", &token)],
                    Some((client, &secret)),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(headers["cache-control"], "no-store");
            body
        }
    };
    // The resource and the client may introspect; others see "inactive".
    let body = ask(access.into(), "ledger", f.ledger_secret.clone()).await;
    assert_eq!(body["active"], true);
    assert_eq!(body["scope"], "Ledger.Read");
    assert_eq!(body["aud"], "api://ledger");
    assert_eq!(body["sub"], f.user.id.to_string());
    let body = ask(access.into(), "web-app", f.web_secret.clone()).await;
    assert_eq!(body["active"], true);
    let orders_secret = common::seed::add_secret(&f.db, &f.orders).await;
    let body = ask(access.into(), "orders", orders_secret).await;
    assert_eq!(body, json!({ "active": false }));
    let body = ask(refresh_token.into(), "web-app", f.web_secret.clone()).await;
    assert_eq!(body["active"], true);
    assert_eq!(body["token_type"], "refresh_token");
    // Public clients can't introspect.
    let (status, _, _) = f
        .post_form(
            "/contoso/oauth2/introspect",
            &[("token", access), ("client_id", "spa-app")],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Revocation: always 200; another client's token is left alone.
    let revoke = |token: &str, client: Option<(&'static str, String)>| {
        let f = &f;
        let token = token.to_owned();
        async move {
            let (form, basic) = match &client {
                Some((id, secret)) => (
                    vec![("token", token.as_str())],
                    Some((*id, secret.as_str())),
                ),
                None => (
                    vec![("token", token.as_str()), ("client_id", "spa-app")],
                    None,
                ),
            };
            f.post_form("/contoso/oauth2/revoke", &form, basic).await.0
        }
    };
    assert_eq!(revoke(access, None).await, StatusCode::OK);
    assert_eq!(
        ask(access.into(), "ledger", f.ledger_secret.clone()).await["active"],
        true
    );
    assert_eq!(
        revoke(access, Some(("web-app", f.web_secret.clone()))).await,
        StatusCode::OK
    );
    assert_eq!(
        ask(access.into(), "ledger", f.ledger_secret.clone()).await["active"],
        false
    );
    assert_eq!(
        revoke(refresh_token, Some(("web-app", f.web_secret.clone()))).await,
        StatusCode::OK
    );
    assert_eq!(
        ask(refresh_token.into(), "web-app", f.web_secret.clone()).await["active"],
        false
    );
    assert_eq!(
        revoke("no-such-token", Some(("web-app", f.web_secret.clone()))).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn client_credentials_returns_app_roles() {
    let f = Fixture::new().await;
    let sync = add_role(&f.db, &f.orders, "Orders.Sync", "application").await;
    assign_role(&f.db, &f.orders, sync, None, Some(f.web.id)).await;
    let basic = Some(("web-app", f.web_secret.as_str()));
    let grant = |scope: &'static str| {
        let f = &f;
        async move {
            let form = [("grant_type", "client_credentials"), ("scope", scope)];
            let (status, _, body) = f.post_form(TOKEN, &form, basic).await;
            (status, body)
        }
    };
    let (status, tokens) = grant("api://orders/.default").await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert_eq!(tokens["scope"], "api://orders/.default");
    assert!(tokens.get("refresh_token").is_none() && tokens.get("id_token").is_none());
    let at = f
        .verify_jwt(tokens["access_token"].as_str().unwrap(), "api://orders")
        .await;
    assert_eq!(at["roles"], json!(["Orders.Sync"]));
    assert_eq!(at["idtyp"], "app");
    assert_eq!(at["sub"], f.web.id.to_string());
    assert!(at.get("scp").is_none());

    // An app without identifier_uri is addressed as api://{client_id}.
    let (status, body) = grant("api://web-app/.default").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // A user-only role assigned to the app never appears in an app token.
    let auditor = add_role(&f.db, &f.orders, "Orders.Auditor", "user").await;
    assign_role(&f.db, &f.orders, auditor, None, Some(f.web.id)).await;
    let (_, tokens) = grant("api://orders/.default").await;
    let at = f
        .verify_jwt(tokens["access_token"].as_str().unwrap(), "api://orders")
        .await;
    assert_eq!(at["roles"], json!(["Orders.Sync"]));
    for bad in [
        "api://orders/Orders.Read",
        "openid api://orders/.default",
        "api://nope/.default",
    ] {
        let (status, body) = grant(bad).await;
        assert_eq!(body["error"], "invalid_scope", "{bad}");
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let form = [
        ("grant_type", "client_credentials"),
        ("scope", "api://orders/.default"),
        ("client_id", "spa-app"),
    ];
    let (_, _, body) = f.post_form(TOKEN, &form, None).await;
    assert_eq!(body["error"], "unauthorized_client");
    let (status, headers, body) = f
        .post_form(TOKEN, &form[..2], Some(("web-app", "wrong")))
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_client"))
    );
    assert!(headers.contains_key("www-authenticate"));
    let (_, _, body) = f
        .post_form(TOKEN, &[("grant_type", "password")], basic)
        .await;
    assert_eq!(body["error"], "unsupported_grant_type");
}
