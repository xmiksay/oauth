// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Subdomain tenancy: which hosts reach a tenant, per-host issuers, and the
//! CSRF origin being the tenant's own.
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{
    ORIGIN, PUBLIC_URL, at,
    browser::{authorize_url, send},
    flow::{Fixture, PASSWORD, WEB_CB},
};
use oauth_server::directory::{self, NewTenant, builtin_apps};
use sea_orm::ConnectionTrait;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn add_fabrikam(f: &Fixture) {
    let new = NewTenant {
        slug: "fabrikam",
        display_name: "Fabrikam",
    };
    directory::create_tenant(&f.db, &f.config, new)
        .await
        .unwrap();
}

async fn status_of(f: &Fixture, req: Request<Body>) -> StatusCode {
    send(&f.app, req).await.0
}

/// Discovery at `uri` with an explicit `Host`: status and `issuer`.
async fn issuer_at(f: &Fixture, uri: &str, host: &str) -> (StatusCode, Value) {
    let req = Request::get(uri)
        .header(header::HOST, host)
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = send(&f.app, req).await;
    let doc: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    (status, doc["issuer"].clone())
}

#[tokio::test]
async fn only_tenant_hosts_reach_a_tenant() {
    let f = Fixture::new().await;
    let discovery = "/.well-known/openid-configuration";
    assert_eq!(
        common::get(&f.app, &format!("{ORIGIN}{discovery}")).await.0,
        StatusCode::OK
    );
    for host in [
        "nope.id.example.test",
        "id.example.test",
        "contoso.id.example.test:8443",
        "contoso.id.example.test:80",
        "contoso.id.example.test.",
        "a.contoso.id.example.test",
        "contoso.evil.example",
        "evil.example",
        "[::1]",
        "127.0.0.1",
    ] {
        let req = Request::get(discovery)
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(&f, req).await, StatusCode::NOT_FOUND, "{host}");
    }
    // Upper case and a spelled-out default port are the same origin; the
    // issuer stays the canonical, port-less one.
    for host in ["Contoso.ID.example.test", "contoso.id.example.test:443"] {
        let issuer = json!(ORIGIN);
        assert_eq!(
            issuer_at(&f, discovery, host).await,
            (StatusCode::OK, issuer),
            "{host}"
        );
    }
    // A forwarded host is never believed, whatever the real host is.
    for host in ["id.example.test", "evil.example"] {
        let req = Request::get(discovery)
            .header(header::HOST, host)
            .header("x-forwarded-host", "contoso.id.example.test")
            .header("forwarded", "host=contoso.id.example.test")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(&f, req).await, StatusCode::NOT_FOUND, "{host}");
    }
    // No host at all (bypassing the helpers' default host).
    let bare = Request::get(discovery).body(Body::empty()).unwrap();
    let resp = f.app.clone().oneshot(bare).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_request_target_authority_wins_over_host() {
    let f = Fixture::new().await;
    let path = "/.well-known/openid-configuration";
    // RFC 9112 §3.2.2: an absolute-form target (or h2 `:authority`) names the host.
    assert_eq!(
        issuer_at(&f, &format!("{ORIGIN}{path}"), "evil.example").await,
        (StatusCode::OK, json!(ORIGIN))
    );
    let (status, _) = issuer_at(&f, &format!("https://evil.example{path}"), common::HOST).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn several_host_headers_are_rejected() {
    let f = Fixture::new().await;
    let mut req = Request::get("/.well-known/openid-configuration")
        .header(header::HOST, common::HOST)
        .body(Body::empty())
        .unwrap();
    req.headers_mut()
        .append(header::HOST, "evil.example".parse().unwrap());
    assert_eq!(status_of(&f, req).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tenants_with_slugs_now_invalid_are_not_served() {
    let f = Fixture::new().await;
    // An M1a-era tenant: `www` and `ab-` passed the old rules.
    f.db.execute_unprepared(
        "INSERT INTO tenants (id, slug, display_name, is_system, disabled) VALUES \
           (gen_random_uuid(), 'www', 'W', false, false), \
           (gen_random_uuid(), 'ab-', 'A', false, false)",
    )
    .await
    .unwrap();
    for slug in ["www", "ab-"] {
        let (status, _) = common::get(&f.app, &at(slug, "/.well-known/openid-configuration")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{slug}");
    }
    // Startup refuses them by name (until renamed or disabled).
    let err = oauth_server::db::migrate_and_reconcile(&f.db, &f.config)
        .await
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("www, ab-") || msg.contains("ab-, www"),
        "{msg}"
    );
    assert!(msg.contains("disable"), "{msg}");
    f.db.execute_unprepared("UPDATE tenants SET disabled = true WHERE slug IN ('www', 'ab-')")
        .await
        .unwrap();
    oauth_server::db::migrate_and_reconcile(&f.db, &f.config)
        .await
        .unwrap();
}

#[tokio::test]
async fn apex_only_redirects_to_the_system_admin_portal() {
    let f = Fixture::new().await;
    let (status, location, _) = f.browser().get(&format!("{PUBLIC_URL}/")).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location.as_deref(),
        Some("https://system.id.example.test/admin")
    );
    for path in ["/admin", "/login", "/oauth2/authorize", "/api/v1/users"] {
        let (status, _) = common::get(&f.app, &format!("{PUBLIC_URL}{path}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    let post = Request::post(format!("{PUBLIC_URL}/"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(&f, post).await, StatusCode::NOT_FOUND);
    // Probes answer on any host (kubelet uses the pod IP).
    for host in [
        "id.example.test",
        "10.0.0.7:8080",
        "contoso.id.example.test",
    ] {
        let req = Request::get("/healthz")
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(&f, req).await, StatusCode::OK, "{host}");
    }
}

#[tokio::test]
async fn every_tenant_host_is_its_own_issuer() {
    let f = Fixture::new().await;
    add_fabrikam(&f).await;
    let mut kids = Vec::new();
    for slug in ["contoso", "fabrikam"] {
        let origin = at(slug, "");
        let (status, body) =
            common::get(&f.app, &at(slug, "/.well-known/openid-configuration")).await;
        assert_eq!(status, StatusCode::OK);
        let doc: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(doc["issuer"], origin.as_str());
        assert_eq!(doc["token_endpoint"], format!("{origin}/oauth2/token"));
        assert_eq!(doc["jwks_uri"], format!("{origin}/discovery/keys"));
        let (_, jwks) = common::get(&f.app, &at(slug, "/discovery/keys")).await;
        let jwks: Value = serde_json::from_str(&jwks).unwrap();
        for key in jwks["keys"].as_array().unwrap() {
            kids.push(key["kid"].as_str().unwrap().to_owned());
        }
    }
    kids.sort();
    kids.dedup();
    assert_eq!(kids.len(), 4, "each host publishes only its own keys");
}

#[tokio::test]
async fn login_api_accepts_only_the_tenants_own_origin() {
    let f = Fixture::new().await;
    add_fabrikam(&f).await;
    let mut browser = f.browser();
    let tx = browser
        .authorize(&authorize_url("web-app", WEB_CB, "openid", &[]))
        .await
        .unwrap();
    let path = format!("/api/authn/tx/{tx}/password");
    let creds = json!({ "email": "ann@example.com", "password": PASSWORD });
    let foreign = at("fabrikam", "");
    for origin in [
        foreign.as_str(),
        PUBLIC_URL,
        "http://contoso.id.example.test",
    ] {
        let (status, _, body) = browser.post_json(&path, &creds, origin).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("csrf_rejected")),
            "{origin}"
        );
    }
    let (status, _, body) = browser.post_json(&path, &creds, ORIGIN).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The logout POST is guarded the same way.
    let (status, _, _) = browser
        .post_json("/oauth2/logout", &json!({}), &foreign)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reconcile_points_builtin_spas_at_the_current_origin() {
    let f = Fixture::new().await;
    // Rows as M1a stored them (path-based), plus a custom app that must stay.
    f.db.execute_unprepared(
        "UPDATE applications SET redirect_uris = ARRAY['https://id.example.test/contoso/admin/callback'], \
           post_logout_redirect_uris = ARRAY['https://id.example.test/contoso/admin'] \
         WHERE builtin AND client_id = 'admin-portal'; \
         UPDATE applications SET redirect_uris = ARRAY['https://custom.example/cb'] \
         WHERE client_id = 'spa-app'",
    )
    .await
    .unwrap();
    let moved = common::test_config(&f.config.database_url, "https://login.example.org:8443");
    oauth_server::db::migrate_and_reconcile(&f.db, &moved)
        .await
        .unwrap();
    let uris = |client_id: &'static str| {
        let f = &f;
        async move {
            let app = common::mgmt::app_by_client_id(&f.db, f.tenant.id, client_id).await;
            (
                app.redirect_uris,
                app.post_logout_redirect_uris,
                app.updated_at,
            )
        }
    };
    let base = "https://contoso.login.example.org:8443";
    for (client_id, area) in [
        (builtin_apps::ADMIN_PORTAL, "admin"),
        (builtin_apps::MY_ACCOUNT, "myaccount"),
    ] {
        let (redirect, post_logout, _) = uris(client_id).await;
        assert_eq!(redirect, [format!("{base}/{area}/callback")], "{client_id}");
        assert_eq!(post_logout, [format!("{base}/{area}")], "{client_id}");
    }
    assert_eq!(uris("spa-app").await.0, ["https://custom.example/cb"]);
    // Idempotent: a second run writes nothing.
    let before = uris(builtin_apps::ADMIN_PORTAL).await.2;
    let changed = builtin_apps::reconcile_all(&f.db, &moved).await.unwrap();
    assert_eq!(changed, 0);
    assert_eq!(uris(builtin_apps::ADMIN_PORTAL).await.2, before);
}

#[test]
fn public_url_with_a_path_is_rejected() {
    let err = common::try_config("postgres://unused", "https://id.example.test/idp").unwrap_err();
    assert!(format!("{err:#}").contains("without path"), "{err:#}");
}
