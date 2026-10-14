// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Management API authentication and the authorization matrix.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{call, mint_app_token, mint_user_token, user_with_roles},
};
use entity::enums::DirectoryRole::{ApplicationAdmin, GlobalAdmin, UserAdmin};
use oauth_server::directory::{self, NewTenant, builtin_apps};
use sea_orm::ConnectionTrait;
use serde_json::{Value, json};

const USERS: &str = "/api/v1/users";
const APPS: &str = "/api/v1/applications";
const ROLES: &str = "/api/v1/directory-roles";
const AUDIT: &str = "/api/v1/audit-events";
const ME: &str = "/api/v1/me";

struct Callers {
    ga: String,
    ua: String,
    aa: String,
    plain: String,
    app_read: String,
    app_rw: String,
    app_none: String,
}

async fn callers(f: &Fixture) -> Callers {
    let (db, cfg, t) = (&f.db, &f.config, &f.tenant);
    let ga = user_with_roles(db, t.id, "ga@example.com", &[GlobalAdmin]).await;
    let ua = user_with_roles(db, t.id, "ua@example.com", &[UserAdmin]).await;
    let aa = user_with_roles(db, t.id, "aa@example.com", &[ApplicationAdmin]).await;
    Callers {
        ga: mint_user_token(db, cfg, t, &ga).await,
        ua: mint_user_token(db, cfg, t, &ua).await,
        aa: mint_user_token(db, cfg, t, &aa).await,
        plain: mint_user_token(db, cfg, t, &f.user).await,
        app_read: mint_app_token(db, cfg, t, Some(builtin_apps::ROLE_READ_ALL)).await,
        app_rw: mint_app_token(db, cfg, t, Some(builtin_apps::ROLE_READ_WRITE_ALL)).await,
        app_none: mint_app_token(db, cfg, t, None).await,
    }
}

async fn status(
    f: &Fixture,
    method: Method,
    path: &str,
    token: &str,
    body: Option<&Value>,
) -> StatusCode {
    call(&f.app, method, path, Some(token), body).await.0
}

#[tokio::test]
async fn permission_matrix_across_endpoints() {
    let f = Fixture::new().await;
    let c = callers(&f).await;
    use StatusCode as S;

    // Reads: any directory role or app role; plain members / role-less apps not.
    for (token, expected) in [
        (&c.ga, S::OK),
        (&c.ua, S::OK),
        (&c.aa, S::OK),
        (&c.app_read, S::OK),
        (&c.app_rw, S::OK),
        (&c.plain, S::FORBIDDEN),
        (&c.app_none, S::FORBIDDEN),
    ] {
        for path in [USERS, APPS, ROLES, AUDIT] {
            assert_eq!(
                status(&f, Method::GET, path, token, None).await,
                expected,
                "{path}"
            );
        }
    }

    // Users: GlobalAdmin, UserAdmin, ReadWrite.All.
    let mut n = 0;
    for (token, expected) in [
        (&c.ga, S::CREATED),
        (&c.ua, S::CREATED),
        (&c.app_rw, S::CREATED),
        (&c.aa, S::FORBIDDEN),
        (&c.app_read, S::FORBIDDEN),
        (&c.plain, S::FORBIDDEN),
    ] {
        n += 1;
        let body = json!({ "email": format!("new{n}@example.com"), "display_name": "New" });
        assert_eq!(
            status(&f, Method::POST, USERS, token, Some(&body)).await,
            expected
        );
    }

    // Applications: GlobalAdmin, ApplicationAdmin, ReadWrite.All.
    for (token, expected) in [
        (&c.ga, S::CREATED),
        (&c.aa, S::CREATED),
        (&c.app_rw, S::CREATED),
        (&c.ua, S::FORBIDDEN),
        (&c.app_read, S::FORBIDDEN),
    ] {
        n += 1;
        let body = json!({ "display_name": format!("App {n}") });
        assert_eq!(
            status(&f, Method::POST, APPS, token, Some(&body)).await,
            expected
        );
    }

    // Directory roles: delegated GlobalAdmin only — never an app.
    for (token, expected) in [
        (&c.ua, S::FORBIDDEN),
        (&c.aa, S::FORBIDDEN),
        (&c.app_rw, S::FORBIDDEN),
        (&c.ga, S::CREATED),
    ] {
        let body = json!({ "user_id": f.user.id, "role": "UserAdmin" });
        assert_eq!(
            status(&f, Method::POST, ROLES, token, Some(&body)).await,
            expected
        );
    }

    // me/… is delegated-only, open to every user.
    assert_eq!(status(&f, Method::GET, ME, &c.plain, None).await, S::OK);
    assert_eq!(
        status(&f, Method::GET, ME, &c.app_rw, None).await,
        S::FORBIDDEN
    );

    // Tenant management lives on the system host only (and no system tenant
    // exists here, so that host is 404 too).
    for path in [
        "/api/v1/tenants".to_owned(),
        common::at("system", "/api/v1/tenants"),
    ] {
        let (st, _) = call(&f.app, Method::GET, &path, Some(&c.ga), None).await;
        assert_eq!(st, S::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn administrators_are_protected_from_lesser_callers() {
    let f = Fixture::new().await;
    let c = callers(&f).await;
    let target = user_with_roles(&f.db, f.tenant.id, "boss@example.com", &[GlobalAdmin]).await;
    let path = format!("{USERS}/{}", target.id);
    let patch = json!({ "display_name": "Renamed" });
    for token in [&c.ua, &c.app_rw] {
        assert_eq!(
            status(&f, Method::PATCH, &path, token, Some(&patch)).await,
            StatusCode::FORBIDDEN
        );
        for action in ["reset-password", "revoke-sessions"] {
            let st = status(
                &f,
                Method::POST,
                &format!("{path}/{action}"),
                token,
                Some(&json!({})),
            )
            .await;
            assert_eq!(st, StatusCode::FORBIDDEN, "{action}");
        }
        assert_eq!(
            status(&f, Method::DELETE, &path, token, None).await,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        status(&f, Method::PATCH, &path, &c.ga, Some(&patch)).await,
        StatusCode::OK
    );
    // A UserAdmin may manage ordinary users.
    let plain = format!("{USERS}/{}", f.user.id);
    assert_eq!(
        status(&f, Method::PATCH, &plain, &c.ua, Some(&patch)).await,
        StatusCode::OK
    );

    // Granting management-API roles is directory write access: GlobalAdmin only.
    let api = common::mgmt::app_by_client_id(&f.db, f.tenant.id, "management-api").await;
    let (_, roles) = call(
        &f.app,
        Method::GET,
        &format!("{APPS}/{}/roles", api.id),
        Some(&c.ga),
        None,
    )
    .await;
    let role_id = roles["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["value"] == "Directory.ReadWrite.All")
        .unwrap()["id"]
        .clone();
    let body = json!({ "app_role_id": role_id, "principal_type": "application", "principal_id": f.web.id });
    let path = "/api/v1/role-assignments";
    for token in [&c.aa, &c.app_rw] {
        assert_eq!(
            status(&f, Method::POST, path, token, Some(&body)).await,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        status(&f, Method::POST, path, &c.ga, Some(&body)).await,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn tokens_are_bound_to_tenant_audience_scope_and_user_state() {
    let f = Fixture::new().await;
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let token = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    assert_eq!(
        status(&f, Method::GET, USERS, &token, None).await,
        StatusCode::OK
    );

    // No / garbage token: 401 with a Bearer challenge.
    let (st, body) = call(&f.app, Method::GET, USERS, None, None).await;
    assert_eq!(
        (st, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_token"))
    );
    assert_eq!(
        status(&f, Method::GET, USERS, "not-a-token", None).await,
        StatusCode::UNAUTHORIZED
    );

    // Another audience: a token for api://orders.
    let (_, tokens) = f
        .web_tokens("api://orders/Orders.Read", "ga@example.com")
        .await;
    let orders = tokens["access_token"].as_str().unwrap();
    assert_eq!(
        status(&f, Method::GET, USERS, orders, None).await,
        StatusCode::UNAUTHORIZED
    );

    // Management audience but without Directory.AccessAsUser.
    let scopeless = common::mgmt::mint_user_token_with(&f.db, &f.config, &f.tenant, &ga, &[]).await;
    assert_eq!(
        status(&f, Method::GET, USERS, &scopeless, None).await,
        StatusCode::FORBIDDEN
    );

    // Another tenant's GlobalAdmin token, presented here.
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
    let foreign_admin =
        user_with_roles(&f.db, other.id, "ga@fabrikam.example", &[GlobalAdmin]).await;
    let foreign = mint_user_token(&f.db, &f.config, &other, &foreign_admin).await;
    assert_eq!(
        status(&f, Method::GET, USERS, &foreign, None).await,
        StatusCode::UNAUTHORIZED
    );
    // …while it works at its own tenant, and contoso's objects are 404 there.
    let fab_users = common::at("fabrikam", "/api/v1/users");
    assert_eq!(
        status(&f, Method::GET, &fab_users, &foreign, None).await,
        StatusCode::OK
    );
    let cross = format!("{fab_users}/{}", f.user.id);
    assert_eq!(
        status(&f, Method::GET, &cross, &foreign, None).await,
        StatusCode::NOT_FOUND
    );

    // Opaque management tokens work too, and die with revocation.
    f.db.execute_unprepared(
        "UPDATE applications SET access_token_format = 'opaque' WHERE client_id = 'management-api'",
    )
    .await
    .unwrap();
    let opaque = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    assert!(!opaque.contains('.'), "opaque token expected");
    assert_eq!(
        status(&f, Method::GET, USERS, &opaque, None).await,
        StatusCode::OK
    );
    let revoke = format!("{USERS}/{}/revoke-sessions", ga.id);
    assert_eq!(
        status(&f, Method::POST, &revoke, &opaque, None).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        status(&f, Method::GET, USERS, &opaque, None).await,
        StatusCode::UNAUTHORIZED
    );

    // A disabled user's tokens stop working at once.
    let second = user_with_roles(&f.db, f.tenant.id, "ga2@example.com", &[GlobalAdmin]).await;
    let second_token = mint_user_token(&f.db, &f.config, &f.tenant, &second).await;
    let disable = json!({ "disabled": true });
    let path = format!("{USERS}/{}", ga.id);
    assert_eq!(
        status(&f, Method::PATCH, &path, &second_token, Some(&disable)).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&f, Method::GET, USERS, &token, None).await,
        StatusCode::UNAUTHORIZED
    );
}
