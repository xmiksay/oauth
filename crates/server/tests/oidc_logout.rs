// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! RP-initiated logout: hint-verified GET, confirmation page, CSRF-protected
//! POST.
mod common;

use axum::http::StatusCode;
use common::{
    PUBLIC_URL,
    browser::{Browser, authorize_url, query_of},
    flow::{Fixture, T, WEB_BYE, WEB_CB},
    seed::add_user,
};
use serde_json::json;

fn logout(extra: &[(&str, &str)]) -> String {
    let q = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(extra)
        .finish();
    format!("/{T}/oauth2/logout?{q}")
}

/// `true` if the browser still has a working session (silent authorize).
async fn signed_in(browser: &mut Browser) -> bool {
    let url = authorize_url("web-app", WEB_CB, "openid", &[("prompt", "none")]);
    let redirect = browser.authorize(&url).await.unwrap_err();
    query_of(&redirect).contains_key("code")
}

#[tokio::test]
async fn logout_without_valid_hint_needs_confirmation() {
    let f = Fixture::new().await;
    let (mut browser, _) = f.web_tokens("openid", "ann@example.com").await;
    let confirm = format!("{PUBLIC_URL}/{T}/logout");

    // No hint, or an invalid one: never an external redirect, session kept.
    for url in [
        logout(&[]),
        logout(&[("post_logout_redirect_uri", WEB_BYE)]),
        logout(&[
            ("id_token_hint", "not.a.jwt"),
            ("post_logout_redirect_uri", WEB_BYE),
        ]),
    ] {
        let (status, location, _) = browser.get(&url).await;
        assert_eq!(status, StatusCode::FOUND, "{url}");
        assert_eq!(location.as_deref(), Some(confirm.as_str()), "{url}");
    }
    assert!(signed_in(&mut browser).await);

    // The confirmation page signs out with a same-origin JSON POST.
    let path = format!("/{T}/oauth2/logout");
    let (status, _, _) = browser
        .post_json(&path, &json!({}), "https://evil.example")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(signed_in(&mut browser).await);
    let (status, _, body) = browser.post_json(&path, &json!({}), PUBLIC_URL).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["signed_out"], true);
    assert!(!browser.has_session());
    assert!(!signed_in(&mut browser).await);
}

#[tokio::test]
async fn logout_with_hint_ends_session_and_redirects() {
    let f = Fixture::new().await;
    let (mut browser, tokens) = f.web_tokens("openid", "ann@example.com").await;
    let id_token = tokens["id_token"].as_str().unwrap().to_owned();
    let stolen = browser.cookies.clone();

    // Unregistered target: rejected, session kept.
    let bad = logout(&[
        ("id_token_hint", &id_token),
        ("post_logout_redirect_uri", "https://evil.example/"),
    ]);
    assert_eq!(browser.get(&bad).await.0, StatusCode::BAD_REQUEST);
    assert!(signed_in(&mut browser).await);

    // Someone else's hint doesn't end this browser's session.
    add_user(&f.db, f.tenant.id, "bob@example.com", false).await;
    let (_, bob) = f.web_tokens("openid", "bob@example.com").await;
    let (status, location, _) = browser
        .get(&logout(&[(
            "id_token_hint",
            bob["id_token"].as_str().unwrap(),
        )]))
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location, Some(format!("{PUBLIC_URL}/{T}/logout")));
    assert!(signed_in(&mut browser).await);

    // A hint-authorized logout without a client target lands on the SPA.
    let (mut other, other_tokens) = f.web_tokens("openid", "ann@example.com").await;
    let hint = other_tokens["id_token"].as_str().unwrap();
    let (status, location, _) = other.get(&logout(&[("id_token_hint", hint)])).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location,
        Some(format!("{PUBLIC_URL}/{T}/logout?signed_out=1"))
    );
    assert!(!other.has_session());

    let target = logout(&[
        ("id_token_hint", &id_token),
        ("post_logout_redirect_uri", WEB_BYE),
        ("state", "bye-1"),
    ]);
    let (status, location, _) = browser.get(&target).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location, Some(format!("{WEB_BYE}?state=bye-1")));
    assert!(!browser.has_session(), "cookie cleared");

    // The server-side session is gone too: the old cookie no longer works.
    browser.cookies = stolen;
    assert!(!signed_in(&mut browser).await);
}
