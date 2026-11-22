// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `APEX_TENANT`: one regular tenant served on the apex host only (issuer,
//! endpoints, cookies, CSRF origin, passkey RP ID and built-in SPA URIs on
//! the apex origin), its subdomain 404, every other tenant unchanged.
mod common;

use axum::{
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{
    ORIGIN, PUBLIC_URL, at,
    authenticator::{Alg, Authenticator, Tweak},
    browser::{authorize_url, send},
    flow::{Fixture, PASSWORD, T, WEB_CB},
    mgmt::{call, mint_user_token},
    passkeys::register_at,
};
use oauth_server::{
    app::{self, AppState},
    db,
    directory::{self, NewTenant, builtin_apps},
};
use sea_orm::ConnectionTrait;
use serde_json::{Value, json};

const DISCOVERY: &str = "/.well-known/openid-configuration";

async fn apex_fixture() -> Fixture {
    apex_fixture_with(false).await
}

async fn apex_fixture_with(telegram: bool) -> Fixture {
    let f = Fixture::with_env(&[("APEX_TENANT", T)], telegram).await;
    let new = NewTenant {
        slug: "fabrikam",
        display_name: "Fabrikam",
    };
    directory::create_tenant(&f.db, &f.config, new)
        .await
        .unwrap();
    f
}

fn apex(path: &str) -> String {
    format!("{PUBLIC_URL}{path}")
}

async fn get_json(f: &Fixture, uri: &str) -> (StatusCode, Value) {
    let (status, body) = common::get(&f.app, uri).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn the_apex_is_the_apex_tenants_only_host() {
    let f = apex_fixture().await;
    let (status, doc) = get_json(&f, &apex(DISCOVERY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["issuer"], PUBLIC_URL);
    assert_eq!(doc["token_endpoint"], apex("/oauth2/token"));
    assert_eq!(doc["jwks_uri"], apex("/discovery/keys"));
    assert_eq!(doc["authorization_endpoint"], apex("/oauth2/authorize"));
    assert_eq!(
        get_json(&f, &apex("/discovery/keys")).await.0,
        StatusCode::OK
    );
    // The management API is there too (and wants a token).
    let users = apex("/api/v1/users");
    assert_eq!(get_json(&f, &users).await.0, StatusCode::UNAUTHORIZED);
    // No redirect to the system admin portal any more.
    assert_ne!(common::get(&f.app, &apex("/")).await.0, StatusCode::FOUND);

    // Its subdomain is gone: one tenant, one origin.
    for path in [
        DISCOVERY,
        "/discovery/keys",
        "/api/v1/users",
        "/oauth2/token",
    ] {
        assert_eq!(
            common::get(&f.app, &at(T, path)).await.0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    // Other tenants keep their subdomain and issuer.
    let (status, doc) = get_json(&f, &at("fabrikam", DISCOVERY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["issuer"], at("fabrikam", ""));
    // Probes still answer on any host.
    assert_eq!(
        common::get(&f.app, &apex("/healthz")).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_telegram_webhook_stays_a_reserved_apex_path() {
    let f = apex_fixture_with(true).await;
    // Reaches the webhook (secret check), not the apex tenant's routes.
    let update = common::telegram::message(42, "private", "hi");
    assert_eq!(
        f.webhook_with(None, &update).await.0,
        StatusCode::UNAUTHORIZED
    );
    let help = f.bot_says(42, "private", "hi").await.unwrap();
    assert!(help.contains("/stop"), "{help}");
}

#[tokio::test]
async fn a_disabled_apex_tenant_is_not_served() {
    let f = apex_fixture().await;
    f.db.execute_unprepared("UPDATE tenants SET disabled = true WHERE slug = 'contoso'")
        .await
        .unwrap();
    assert_eq!(
        common::get(&f.app, &apex(DISCOVERY)).await.0,
        StatusCode::NOT_FOUND
    );
}

/// The `Set-Cookie` named `name`, asserting it is host-only (`__Host-`, no
/// `Domain`, `Path=/`).
fn host_only_cookie(headers: &HeaderMap, name: &str) {
    let cookie = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .find(|c| c.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name} cookie in {headers:?}"));
    assert!(!cookie.to_ascii_lowercase().contains("domain"), "{cookie}");
    assert!(
        cookie.contains("Path=/;") || cookie.ends_with("Path=/"),
        "{cookie}"
    );
}

fn jwt_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

#[tokio::test]
async fn sign_in_tokens_and_csrf_use_the_apex_origin() {
    let f = apex_fixture().await;
    let mut browser = f.browser();
    let url = apex(&authorize_url("web-app", WEB_CB, "openid", &[]));
    let (status, location, body) = browser.get(&url).await;
    assert_eq!(status, StatusCode::FOUND, "{body}");
    let location = location.unwrap();
    let tx = location
        .strip_prefix(&apex("/login?tx="))
        .unwrap_or_else(|| panic!("login page off the apex: {location}"))
        .to_owned();
    assert!(browser.cookies.contains_key("__Host-oauth_tx"));

    let path = apex(&format!("/api/authn/tx/{tx}/password"));
    let creds = json!({ "email": "ann@example.com", "password": PASSWORD });
    // The old subdomain origin is foreign now, like any other.
    for origin in [ORIGIN, at("fabrikam", "").as_str()] {
        let (status, _, body) = browser.post_json(&path, &creds, origin).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("csrf_rejected")),
            "{origin}"
        );
    }
    let (status, headers, mut resp) = browser.post_json(&path, &creds, PUBLIC_URL).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    host_only_cookie(&headers, "__Host-oauth_sid");
    if resp["step"] == "consent" {
        let step = apex(&format!("/api/authn/tx/{tx}/consent"));
        let scopes = json!({ "approve": true, "scopes": ["openid"] });
        (_, _, resp) = browser.post_json(&step, &scopes, PUBLIC_URL).await;
    }
    let redirect = resp["redirect"]
        .as_str()
        .unwrap_or_else(|| panic!("{resp}"));
    let q = common::browser::query_of(redirect);
    assert_eq!(q.get("iss").map(String::as_str), Some(PUBLIC_URL));
    let code = q["code"].clone();

    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", WEB_CB),
        ("code_verifier", common::flow::VERIFIER),
    ];
    let basic = Some(("web-app", f.web_secret.as_str()));
    let (status, _, tokens) = f.post_form(&apex("/oauth2/token"), &form, basic).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let claims = jwt_claims(tokens["id_token"].as_str().unwrap());
    assert_eq!(claims["iss"], PUBLIC_URL);

    // Signing out: the logout POST wants the apex origin too.
    let logout = apex("/oauth2/logout");
    let (status, _, _) = browser.post_json(&logout, &json!({}), ORIGIN).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn passkeys_and_the_management_api_live_on_the_apex() {
    let f = apex_fixture().await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &f.user).await;
    let (status, me) = call(&f.app, Method::GET, &apex("/api/v1/me"), Some(&token), None).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    // RP ID = the apex host, origin = the apex origin.
    let mut auth = Authenticator::new(Alg::Es256, T);
    auth.rp_id = "id.example.test".into();
    auth.origin = PUBLIC_URL.into();
    let reauth = json!({ "password": PASSWORD });
    let (status, body) = register_at(
        &f.app,
        PUBLIC_URL,
        &token,
        &mut auth,
        reauth,
        &Tweak::default(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    // A ceremony bound to the old subdomain is refused.
    let mut old = Authenticator::new(Alg::Es256, T);
    let reauth = json!({ "password": PASSWORD });
    let (status, _) = register_at(
        &f.app,
        PUBLIC_URL,
        &token,
        &mut old,
        reauth,
        &Tweak::default(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_apex_tenant_cannot_be_disabled() {
    let f = apex_fixture().await;
    let (f, _system, _root, token) = common::tenant_users::setup_on(f).await;
    let sys = |path: &str| at("system", path);
    let off = json!({ "disabled": true });
    let (status, body) = call(
        &f.app,
        Method::PATCH,
        &sys(&format!("/api/v1/tenants/{T}")),
        Some(&token),
        Some(&off),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = call(
        &f.app,
        Method::PATCH,
        &sys("/api/v1/tenants/fabrikam"),
        Some(&token),
        Some(&off),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The list names each tenant's origin.
    let (_, list) = call(
        &f.app,
        Method::GET,
        &sys("/api/v1/tenants"),
        Some(&token),
        None,
    )
    .await;
    let origin_of = |slug: &str| {
        list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["slug"] == slug)
            .map(|t| t["origin"].clone())
            .unwrap()
    };
    assert_eq!(origin_of(T), PUBLIC_URL);
    assert_eq!(origin_of("fabrikam"), at("fabrikam", ""));
    assert_eq!(origin_of("system"), at("system", ""));
}

#[tokio::test]
async fn startup_requires_an_enabled_regular_apex_tenant() {
    let f = Fixture::new().await;
    let with_apex = |slug: &str| {
        common::config_with(&f.config.database_url, PUBLIC_URL, &[("APEX_TENANT", slug)]).unwrap()
    };
    let err = db::migrate_and_reconcile(&f.db, &with_apex("nope"))
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("no such tenant"), "{err:#}");
    f.db.execute_unprepared("UPDATE tenants SET disabled = true WHERE slug = 'contoso'")
        .await
        .unwrap();
    let err = db::migrate_and_reconcile(&f.db, &with_apex(T))
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("disabled"), "{err:#}");
    f.db.execute_unprepared("UPDATE tenants SET disabled = false WHERE slug = 'contoso'")
        .await
        .unwrap();

    // Accepted, and the built-in SPAs move to the apex — and back once unset.
    let admin_uris = || async {
        let app =
            common::mgmt::app_by_client_id(&f.db, f.tenant.id, builtin_apps::ADMIN_PORTAL).await;
        (app.redirect_uris, app.post_logout_redirect_uris)
    };
    db::migrate_and_reconcile(&f.db, &with_apex(T))
        .await
        .unwrap();
    assert_eq!(
        admin_uris().await,
        (vec![apex("/admin/callback")], vec![apex("/admin")])
    );
    let my = common::mgmt::app_by_client_id(&f.db, f.tenant.id, builtin_apps::MY_ACCOUNT).await;
    assert_eq!(my.redirect_uris, [apex("/myaccount/callback")]);
    db::migrate_and_reconcile(&f.db, &f.config).await.unwrap();
    assert_eq!(
        admin_uris().await,
        (vec![at(T, "/admin/callback")], vec![at(T, "/admin")])
    );
}

#[tokio::test]
async fn the_spa_is_told_its_tenant() {
    let (_pg, conn, config) = common::migrated_db_with(&[("APEX_TENANT", T)]).await;
    for slug in [T, "fabrikam"] {
        let new = NewTenant {
            slug,
            display_name: slug,
        };
        directory::create_tenant(&conn, &config, new).await.unwrap();
    }
    let dist = tempfile::tempdir().unwrap();
    std::fs::write(
        dist.path().join("index.html"),
        "<html><head><title>oauth</title></head><body></body></html>",
    )
    .unwrap();
    let app = app::router(AppState::new(conn, config, true), dist.path());
    for (uri, slug) in [
        (apex("/"), T),
        (apex("/admin/users"), T),
        (at("fabrikam", "/login"), "fabrikam"),
    ] {
        let req = Request::get(&uri).body(Body::empty()).unwrap();
        let (status, headers, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        let meta = format!(r#"<meta name="oauth-tenant" content="{slug}" /></head>"#);
        assert!(body.contains(&meta), "{uri}: {body}");
        assert_eq!(headers[header::CACHE_CONTROL], "no-cache", "{uri}");
    }
    let req = Request::get(at(T, "/")).body(Body::empty()).unwrap();
    assert_eq!(send(&app, req).await.0, StatusCode::NOT_FOUND);
}
