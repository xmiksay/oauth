// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! CORS on the protocol endpoints: preflights and actual responses for
//! allowed, foreign and other-tenant origins; none on the login and
//! management APIs.
mod common;

use axum::{
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{
    ORIGIN, at,
    browser::send,
    flow::Fixture,
    mgmt::{app_admin_token, call},
    seed::add_app,
};
use entity::{
    applications,
    enums::{AccessTokenFormat, ClientType, SigningAlg},
};
use oauth_server::directory::{self, NewTenant};
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use serde_json::json;

/// `spa-app` (public) gets this from its `https://web.example/cb` redirect.
const SPA_ORIGIN: &str = "https://web.example";
/// Explicitly allowed on the confidential `web-app` only.
const WEB_ORIGIN: &str = "https://portal.example";
const FOREIGN: &str = "https://evil.example";
const ACAO: header::HeaderName = header::ACCESS_CONTROL_ALLOW_ORIGIN;

async fn request(
    f: &Fixture,
    method: Method,
    uri: &str,
    headers: &[(header::HeaderName, &str)],
    form: Option<&[(&str, &str)]>,
) -> (StatusCode, HeaderMap) {
    let mut req = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        req = req.header(name, *value);
    }
    let body = match form {
        Some(form) => {
            req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(
                form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(form)
                    .finish(),
            )
        }
        None => Body::empty(),
    };
    let (status, headers, _) = send(&f.app, req.body(body).unwrap()).await;
    (status, headers)
}

fn acao(headers: &HeaderMap) -> Option<&str> {
    headers.get(ACAO).map(|v| v.to_str().unwrap())
}

fn assert_cors(headers: &HeaderMap, allowed: Option<&str>, what: &str) {
    assert_eq!(acao(headers), allowed, "{what}");
    let vary: Vec<_> = headers.get_all(header::VARY).iter().collect();
    assert!(vary.iter().any(|v| *v == "Origin"), "{what}: Vary {vary:?}");
    assert!(
        !headers.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
        "{what}"
    );
}

async fn fixture() -> Fixture {
    let f = Fixture::new().await;
    let mut web: applications::ActiveModel = f.web.clone().into();
    web.web_origins = Set(vec![WEB_ORIGIN.into()]);
    web.update(&f.db).await.unwrap();
    f
}

async fn preflight(f: &Fixture, uri: &str, origin: &str, method: &str) -> HeaderMap {
    let headers = [
        (header::ORIGIN, origin),
        (header::ACCESS_CONTROL_REQUEST_METHOD, method),
        (header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization"),
    ];
    let (status, out) = request(f, Method::OPTIONS, uri, &headers, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{uri}");
    out
}

#[tokio::test]
async fn discovery_jwks_userinfo_allow_any_origin_of_the_tenant() {
    let f = fixture().await;
    for path in [
        "/.well-known/openid-configuration",
        "/discovery/keys",
        "/oauth2/userinfo",
    ] {
        for (origin, allowed) in [
            (SPA_ORIGIN, Some(SPA_ORIGIN)),
            (WEB_ORIGIN, Some(WEB_ORIGIN)),
            ("http://127.0.0.1", Some("http://127.0.0.1")),
            (FOREIGN, None),
            ("null", None),
            // Same-origin needs (and gets) no CORS.
            (ORIGIN, None),
        ] {
            let (_, headers) =
                request(&f, Method::GET, path, &[(header::ORIGIN, origin)], None).await;
            assert_cors(&headers, allowed, &format!("{path} from {origin}"));
        }
        let (_, headers) = request(&f, Method::GET, path, &[], None).await;
        assert_cors(&headers, None, &format!("{path} without Origin"));
    }
    // The real payload is readable, e.g. a 401 from userinfo.
    let (status, headers) = request(
        &f,
        Method::GET,
        "/oauth2/userinfo",
        &[(header::ORIGIN, SPA_ORIGIN)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(acao(&headers), Some(SPA_ORIGIN));
}

#[tokio::test]
async fn preflights_answer_only_registered_origins_and_methods() {
    let f = fixture().await;
    let cases = [
        ("/.well-known/openid-configuration", "GET", "GET"),
        ("/discovery/keys", "GET", "GET"),
        ("/oauth2/userinfo", "GET", "GET, POST"),
        ("/oauth2/userinfo", "POST", "GET, POST"),
        // Token / revoke preflights can't know the client: any app's origin.
        ("/oauth2/token", "POST", "POST"),
        ("/oauth2/revoke", "POST", "POST"),
    ];
    for (path, method, methods) in cases {
        for origin in [SPA_ORIGIN, WEB_ORIGIN] {
            let headers = preflight(&f, path, origin, method).await;
            assert_cors(&headers, Some(origin), path);
            assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_METHODS], methods);
            assert_eq!(
                headers[header::ACCESS_CONTROL_ALLOW_HEADERS],
                "authorization, content-type"
            );
            assert!(headers.contains_key(header::ACCESS_CONTROL_MAX_AGE));
        }
        let headers = preflight(&f, path, FOREIGN, method).await;
        assert_cors(&headers, None, path);
        assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_METHODS));
    }
    let headers = preflight(&f, "/oauth2/token", SPA_ORIGIN, "DELETE").await;
    assert_cors(&headers, None, "unsupported method");
    let headers = preflight(&f, "/discovery/keys", SPA_ORIGIN, "POST").await;
    assert_cors(&headers, None, "JWKS is GET only");
}

#[tokio::test]
async fn token_and_revoke_echo_only_the_named_clients_origins() {
    let f = fixture().await;
    let spa_form: &[(&str, &str)] = &[
        ("grant_type", "authorization_code"),
        ("client_id", "spa-app"),
        ("code", "bogus"),
        ("redirect_uri", "https://web.example/cb"),
        ("code_verifier", "v"),
    ];
    for (origin, allowed) in [
        (SPA_ORIGIN, Some(SPA_ORIGIN)),
        // web-app's explicit origin is not spa-app's.
        (WEB_ORIGIN, None),
        (FOREIGN, None),
    ] {
        let headers = [(header::ORIGIN, origin)];
        let (status, out) =
            request(&f, Method::POST, "/oauth2/token", &headers, Some(spa_form)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "invalid_grant is readable");
        assert_cors(&out, allowed, &format!("token from {origin}"));
        let revoke: &[(&str, &str)] = &[("client_id", "spa-app"), ("token", "unknown")];
        let (status, out) =
            request(&f, Method::POST, "/oauth2/revoke", &headers, Some(revoke)).await;
        assert_eq!(status, StatusCode::OK);
        assert_cors(&out, allowed, &format!("revoke from {origin}"));
    }

    // Confidential web-app: its redirect URIs' origins don't count, its
    // explicit origin does — also for a failed authentication.
    let basic = format!("Basic {}", STANDARD.encode("web-app:wrong"));
    let form: &[(&str, &str)] = &[("grant_type", "client_credentials")];
    for (origin, allowed) in [(WEB_ORIGIN, Some(WEB_ORIGIN)), (SPA_ORIGIN, None)] {
        let headers = [
            (header::ORIGIN, origin),
            (header::AUTHORIZATION, basic.as_str()),
        ];
        let (status, out) = request(&f, Method::POST, "/oauth2/token", &headers, Some(form)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_cors(&out, allowed, &format!("web-app from {origin}"));
    }

    // No (or an unknown) client named: nothing to allow.
    for form in [
        &[("grant_type", "client_credentials")][..],
        &[
            ("client_id", "nobody"),
            ("grant_type", "client_credentials"),
        ][..],
    ] {
        let headers = [(header::ORIGIN, SPA_ORIGIN)];
        let (_, out) = request(&f, Method::POST, "/oauth2/token", &headers, Some(form)).await;
        assert_cors(&out, None, "no client");
    }
}

#[tokio::test]
async fn another_tenants_origins_are_refused() {
    let f = fixture().await;
    let other = directory::create_tenant(
        &f.db,
        &f.config,
        NewTenant {
            slug: "fabrikam",
            display_name: "Fabrikam",
        },
    )
    .await
    .unwrap();
    let fab = add_app(
        &f.db,
        other.id,
        "fab-app",
        ClientType::Confidential,
        None,
        AccessTokenFormat::Jwt,
        SigningAlg::Rs256,
    )
    .await;
    let mut row: applications::ActiveModel = fab.into();
    row.web_origins = Set(vec!["https://fab.example".into()]);
    row.update(&f.db).await.unwrap();

    let origin = [(header::ORIGIN, "https://fab.example")];
    let path = "/.well-known/openid-configuration";
    let (_, headers) = request(&f, Method::GET, path, &origin, None).await;
    assert_cors(&headers, None, "contoso refuses fabrikam's origin");
    let (_, headers) = request(&f, Method::GET, &at("fabrikam", path), &origin, None).await;
    assert_cors(&headers, Some("https://fab.example"), "fabrikam allows it");
    let headers = preflight(&f, "/oauth2/token", "https://fab.example", "POST").await;
    assert_cors(&headers, None, "token preflight on contoso");
    // fab-app named on contoso's token endpoint is an unknown client there.
    let form: &[(&str, &str)] = &[("client_id", "fab-app"), ("token", "x")];
    let (_, headers) = request(&f, Method::POST, "/oauth2/revoke", &origin, Some(form)).await;
    assert_cors(&headers, None, "revoke on contoso");
}

#[tokio::test]
async fn login_and_management_apis_never_grant_cors() {
    let f = fixture().await;
    for path in [
        "/api/v1/applications",
        "/api/authn/tx/x",
        "/oauth2/introspect",
    ] {
        let (_, headers) = request(
            &f,
            Method::OPTIONS,
            path,
            &[
                (header::ORIGIN, SPA_ORIGIN),
                (header::ACCESS_CONTROL_REQUEST_METHOD, "POST"),
            ],
            None,
        )
        .await;
        assert_eq!(acao(&headers), None, "{path}");
        let (_, headers) =
            request(&f, Method::GET, path, &[(header::ORIGIN, SPA_ORIGIN)], None).await;
        assert_eq!(acao(&headers), None, "{path}");
    }
}

#[tokio::test]
async fn web_origins_through_the_management_api() {
    let f = fixture().await;
    let token = app_admin_token(&f).await;
    let path = format!("/api/v1/applications/{}", f.spa.id);
    let patch = |body| {
        let (app, path, token) = (f.app.clone(), path.clone(), token.clone());
        async move { call(&app, Method::PATCH, &path, Some(&token), Some(&body)).await }
    };
    let (st, app) = patch(json!({ "web_origins": ["https://spa2.example:8443"] })).await;
    assert_eq!(st, StatusCode::OK, "{app}");
    assert_eq!(app["web_origins"], json!(["https://spa2.example:8443"]));
    assert_eq!(
        app["effective_web_origins"],
        json!(["https://spa2.example:8443", SPA_ORIGIN, "http://127.0.0.1"])
    );
    let audit = common::mgmt::audited(&f.db, "application.update", f.spa.id).await;
    assert_eq!(audit.last().unwrap()["fields"], json!(["web_origins"]));
    let (_, headers) = request(
        &f,
        Method::GET,
        "/discovery/keys",
        &[(header::ORIGIN, "https://spa2.example:8443")],
        None,
    )
    .await;
    assert_cors(&headers, Some("https://spa2.example:8443"), "new origin");

    for bad in [
        json!({ "web_origins": ["https://a.example/"] }),
        json!({ "web_origins": ["https://*.example"] }),
        json!({ "web_origins": ["http://a.example"] }),
        json!({ "web_origins": ["https://A.example"] }),
        json!({ "web_origins": ["https://a.example:443"] }),
        json!({ "web_origins": ["https://a.example", "https://a.example"] }),
    ] {
        let (st, body) = patch(bad.clone()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }

    // Built-in apps keep theirs fixed.
    let builtin = common::mgmt::app_by_client_id(&f.db, f.tenant.id, "admin-portal").await;
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        &format!("/api/v1/applications/{}", builtin.id),
        Some(&token),
        Some(&json!({ "web_origins": [SPA_ORIGIN] })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}
