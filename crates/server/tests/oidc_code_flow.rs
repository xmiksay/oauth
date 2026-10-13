// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Authorization code flow end to end: discovery, login with TOTP and
//! consent, tokens verified against JWKS, userinfo, session reuse.
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{
    PUBLIC_URL,
    browser::{authorize_url, current_totp, query_of, send},
    flow::{Fixture, SPA_CB, T, WEB_CB},
};
use serde_json::{Value, json};

#[tokio::test]
async fn discovery_and_jwks() {
    let f = Fixture::new().await;
    let get = |path: String| send(&f.app, Request::get(path).body(Body::empty()).unwrap());
    let (status, _, body) = get(format!("/{T}/.well-known/openid-configuration")).await;
    assert_eq!(status, StatusCode::OK);
    let doc: Value = serde_json::from_str(&body).unwrap();
    let issuer = format!("{PUBLIC_URL}/{T}");
    assert_eq!(doc["issuer"], issuer);
    assert_eq!(
        doc["authorization_endpoint"],
        format!("{issuer}/oauth2/authorize")
    );
    assert_eq!(doc["jwks_uri"], format!("{issuer}/discovery/keys"));
    assert_eq!(doc["response_types_supported"], json!(["code"]));
    assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        doc["id_token_signing_alg_values_supported"],
        json!(["RS256", "ES256"])
    );

    let (status, headers, body) = get(format!("/{T}/discovery/keys")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("max-age")
    );
    let jwks: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 2);

    for path in [
        "/nope/.well-known/openid-configuration",
        "/Bad_Slug/discovery/keys",
    ] {
        assert_eq!(get(path.into()).await.0, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn confidential_client_with_totp_and_consent() {
    let f = Fixture::new().await;
    f.enroll_totp(&f.user).await;
    let mut browser = f.browser();
    let scope = "openid profile email offline_access api://orders/Orders.Read";
    let url = authorize_url("web-app", WEB_CB, scope, &[]);
    let tx = browser.authorize(&url).await.expect("login page");

    // The SPA's view of the transaction.
    let (status, _, body) = browser.get(&format!("/{T}/api/authn/tx/{tx}")).await;
    assert_eq!(status, StatusCode::OK);
    let view: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(view["step"], "password");
    assert_eq!(view["client"]["client_id"], "web-app");
    assert_eq!(view["tenant"]["slug"], T);

    let (status, resp) = browser
        .step(
            &tx,
            "password",
            json!({ "email": "ANN@example.com", "password": common::flow::PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["step"], "mfa");
    let (status, resp) = browser.step(&tx, "totp", json!({ "code": "abcdef" })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{resp}");
    assert_eq!(resp["error"], "invalid_code");
    let code = current_totp();
    let (status, resp) = browser.step(&tx, "totp", json!({ "code": code })).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["step"], "consent");
    assert_eq!(resp["consent"]["resource"]["audience"], "api://orders");
    assert_eq!(resp["consent"]["scopes"][0]["value"], "Orders.Read");
    assert!(
        !browser.has_session(),
        "no session before the flow completes"
    );

    // Approving must list what was shown.
    let (status, _) = browser
        .step(&tx, "consent", json!({ "approve": true, "scopes": [] }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, resp) = browser
        .step(
            &tx,
            "consent",
            json!({ "approve": true, "scopes": ["Orders.Read"] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let redirect = resp["redirect"].as_str().unwrap();
    assert!(
        redirect.starts_with(&format!("{WEB_CB}?code=")),
        "{redirect}"
    );
    let q = query_of(redirect);
    assert_eq!(q["state"], "st-1");
    assert_eq!(q["iss"], format!("{PUBLIC_URL}/{T}"));
    assert!(browser.has_session());
    // The transaction is gone once used.
    assert_eq!(
        browser.get(&format!("/{T}/api/authn/tx/{tx}")).await.0,
        StatusCode::NOT_FOUND
    );

    // Wrong secret, wrong verifier and wrong redirect are refused…
    let (status, body) = f.redeem(&f.web, Some("wrong"), &q["code"], WEB_CB).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_client"))
    );
    let (status, body) = f
        .redeem(&f.web, Some(&f.web_secret), &q["code"], SPA_CB)
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    // …and the code still works afterwards.
    let (status, tokens) = f
        .redeem(&f.web, Some(&f.web_secret), &q["code"], WEB_CB)
        .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(
        tokens["scope"],
        "api://orders/Orders.Read openid profile email offline_access"
    );
    assert!(tokens["refresh_token"].is_string());

    // Access token: ES256 (resource setting), RFC 9068 shape.
    let access = tokens["access_token"].as_str().unwrap();
    let header = jsonwebtoken::decode_header(access).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::ES256);
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    let at = f.verify_jwt(access, "api://orders").await;
    assert_eq!(at["sub"], f.user.id.to_string());
    assert_eq!(at["oid"], f.user.id.to_string());
    assert_eq!(at["tid"], f.tenant.id.to_string());
    assert_eq!(at["azp"], "web-app");
    assert_eq!(at["client_id"], "web-app");
    assert_eq!(at["scp"], "Orders.Read");
    assert_eq!(at["roles"], json!(["Orders.Approver"]));
    assert_eq!(at["groups"], json!([f.group.to_string()]));
    assert_eq!(at["amr"], json!(["pwd", "otp", "mfa"]));
    assert_eq!(at["ver"], "2.0");

    // ID token: RS256 (client setting), nonce, at_hash.
    let id_token = tokens["id_token"].as_str().unwrap();
    assert_eq!(
        jsonwebtoken::decode_header(id_token).unwrap().alg,
        jsonwebtoken::Algorithm::RS256
    );
    let id = f.verify_jwt(id_token, "web-app").await;
    assert_eq!(id["nonce"], "n-1");
    assert_eq!(id["email"], "ann@example.com");
    assert_eq!(id["name"], "Test User");
    assert_eq!(id["sid"], at["sid"]);
    assert!(id["at_hash"].is_string());

    // A resource token is not a userinfo token.
    let userinfo = |token: String| {
        let req = Request::get(format!("/{T}/oauth2/userinfo"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        send(&f.app, req)
    };
    assert_eq!(
        userinfo(access.to_owned()).await.0,
        StatusCode::UNAUTHORIZED
    );

    // Second request: session and consent are reused — no login page.
    let url = authorize_url("web-app", WEB_CB, "openid profile email", &[]);
    let code = browser.login_for_code(&url, "unused").await;
    let (status, tokens) = f.redeem(&f.web, Some(&f.web_secret), &code, WEB_CB).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert!(
        tokens.get("refresh_token").is_none(),
        "no offline_access requested"
    );
    let oidc_access = tokens["access_token"].as_str().unwrap().to_owned();
    f.verify_jwt(&oidc_access, &format!("{PUBLIC_URL}/{T}/oauth2/userinfo"))
        .await;
    let (status, headers, body) = userinfo(oidc_access).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let info: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(info["sub"], f.user.id.to_string());
    assert_eq!(info["email"], "ann@example.com");
    assert_eq!(info["email_verified"], false);
    assert_eq!(info["preferred_username"], "ann@example.com");
    assert_eq!(userinfo("garbage".into()).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn public_client_with_loopback_redirect() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    let redirect = "http://127.0.0.1:53124/cb";
    let url = authorize_url("spa-app", redirect, "openid offline_access", &[]);
    let code = browser.login_for_code(&url, "ann@example.com").await;
    // Public clients authenticate with client_id only; a secret is refused.
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect),
        ("code_verifier", common::flow::VERIFIER),
        ("client_id", "spa-app"),
        ("client_secret", "x"),
    ];
    let (status, _, body) = f
        .post_form(&format!("/{T}/oauth2/token"), &form, None)
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_client"))
    );
    let (status, tokens) = f.redeem(&f.spa, None, &code, redirect).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert!(
        tokens["refresh_token"].is_string(),
        "public clients get rotating refresh tokens"
    );
    let id = f
        .verify_jwt(tokens["id_token"].as_str().unwrap(), "spa-app")
        .await;
    assert_eq!(id["amr"], json!(["pwd"]));
    assert!(id.get("email").is_none(), "email scope not requested");
}

#[tokio::test]
async fn authorize_rejects_bad_requests() {
    let f = Fixture::new().await;
    let mut browser = f.browser();
    // Unvalidated client or redirect: rendered, never redirected.
    for url in [
        authorize_url("nobody", WEB_CB, "openid", &[]),
        authorize_url("web-app", "https://evil.example/cb", "openid", &[]),
        authorize_url("web-app", "http://127.0.0.1:8080/other", "openid", &[]),
        format!("/{T}/oauth2/authorize?client_id=web-app&client_id=spa-app"),
    ] {
        let (status, location, body) = browser.get(&url).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{url}: {body}");
        assert!(location.is_none());
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["error"],
            "invalid_request"
        );
    }
    // Validated client + redirect: errors go back to the client with state.
    let cases = [
        (
            authorize_url("web-app", WEB_CB, "openid", &[("response_type", "token")]),
            "unsupported_response_type",
        ),
        (
            authorize_url(
                "web-app",
                WEB_CB,
                "openid",
                &[("code_challenge_method", "plain")],
            ),
            "invalid_request",
        ),
        (
            authorize_url("web-app", WEB_CB, "openid", &[("code_challenge", "")]),
            "invalid_request",
        ),
        (authorize_url("web-app", WEB_CB, "", &[]), "invalid_scope"),
        (
            authorize_url(
                "web-app",
                WEB_CB,
                "api://orders/Orders.Read api://ledger/Ledger.Read",
                &[],
            ),
            "invalid_scope",
        ),
        (
            authorize_url("web-app", WEB_CB, "api://orders/Nope", &[]),
            "invalid_scope",
        ),
        (
            authorize_url("web-app", WEB_CB, "api://unknown/x", &[]),
            "invalid_scope",
        ),
        (
            authorize_url("web-app", WEB_CB, "openid", &[("prompt", "none login")]),
            "invalid_request",
        ),
        (
            authorize_url("web-app", WEB_CB, "openid", &[("request", "eyJ")]),
            "request_not_supported",
        ),
    ];
    for (url, error) in cases {
        let redirect = browser
            .authorize(&url)
            .await
            .expect_err("should redirect to client");
        assert!(redirect.starts_with(WEB_CB), "{redirect}");
        let q = query_of(&redirect);
        assert_eq!(q["error"], error, "{url}");
        assert_eq!(q["state"], "st-1");
    }
    // response_type=token appended twice is a duplicate → rendered error.
    let url = format!(
        "{}&response_type=token",
        authorize_url("web-app", WEB_CB, "openid", &[])
    );
    assert_eq!(browser.get(&url).await.0, StatusCode::BAD_REQUEST);
}
