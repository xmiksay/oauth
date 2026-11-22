// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `SYSTEM_TENANT_SLUG` / `SYSTEM_TENANT_RENAME`: a fresh install under a
//! custom slug, a mismatch refused at startup, the opt-in rename and its
//! collision check.
mod common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use entity::{audit_events, tenants};
use oauth_server::{
    app::{self, AppState},
    bootstrap::{self, Options},
    config::Config,
    db,
    directory::{self, NewTenant, builtin_apps},
};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter};

use common::{PUBLIC_URL, TestDb};

fn opts() -> Options {
    Options {
        admin_email: "root@example.com".into(),
        display_name: None,
        reset_password: false,
    }
}

fn config(pg: &TestDb, extra: &[(&'static str, &str)]) -> Config {
    common::config_with(&pg.url, PUBLIC_URL, extra).unwrap()
}

/// A database bootstrapped with the default `system` slug.
async fn bootstrapped() -> (TestDb, DatabaseConnection) {
    let pg = common::start_postgres().await;
    let conn = db::connect(&pg.url).await.unwrap();
    bootstrap::run(&conn, &config(&pg, &[]), &opts())
        .await
        .unwrap();
    (pg, conn)
}

async fn system(conn: &DatabaseConnection) -> tenants::Model {
    directory::find_system_tenant(conn).await.unwrap().unwrap()
}

async fn renames(conn: &DatabaseConnection) -> u64 {
    audit_events::Entity::find()
        .filter(audit_events::Column::EventType.eq("tenant.rename"))
        .count(conn)
        .await
        .unwrap()
}

async fn admin_portal_redirects(conn: &DatabaseConnection, tenant_id: uuid::Uuid) -> Vec<String> {
    common::mgmt::app_by_client_id(conn, tenant_id, builtin_apps::ADMIN_PORTAL)
        .await
        .redirect_uris
}

async fn apex_redirect(conn: &DatabaseConnection, config: &Config) -> Option<String> {
    let state = AppState::new(conn.clone(), config.clone(), true);
    let router = app::router(state, common::no_web_dist());
    let req = Request::get(format!("{PUBLIC_URL}/"))
        .header(header::HOST, "id.example.test")
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = common::browser::send(&router, req).await;
    assert_eq!(status, StatusCode::FOUND);
    headers
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap().to_owned())
}

#[tokio::test]
async fn fresh_install_uses_the_configured_slug() {
    let pg = common::start_postgres().await;
    let conn = db::connect(&pg.url).await.unwrap();
    let cfg = config(&pg, &[("SYSTEM_TENANT_SLUG", "config")]);

    let report = bootstrap::run(&conn, &cfg, &opts()).await.unwrap();
    assert!(report.render().contains("Created tenant `config`"));
    let tenant = system(&conn).await;
    assert_eq!(tenant.slug, "config");
    assert_eq!(
        admin_portal_redirects(&conn, tenant.id).await,
        ["https://config.id.example.test/admin/callback"]
    );
    db::migrate_and_reconcile(&conn, &cfg).await.unwrap();
    assert_eq!(
        apex_redirect(&conn, &cfg).await.as_deref(),
        Some("https://config.id.example.test/admin")
    );
    // Its Global Admin learns from `me` that this host manages tenants.
    let root = directory::find_user_by_email(&conn, tenant.id, "root@example.com")
        .await
        .unwrap()
        .unwrap();
    let token = common::mgmt::mint_user_token(&conn, &cfg, &tenant, &root).await;
    let state = AppState::new(conn.clone(), cfg.clone(), true);
    let router = app::router(state, common::no_web_dist());
    let me_url = common::at("config", "/api/v1/me");
    let (status, me) = common::mgmt::call(&router, Method::GET, &me_url, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["tenant_is_system"], true);
    // Both the configured slug and the default stay out of reach of regular tenants.
    for slug in ["config", "system"] {
        let new = NewTenant {
            slug,
            display_name: "Taken",
        };
        let err = directory::create_tenant(&conn, &cfg, new)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("reserved"), "{slug}: {err}");
    }
}

#[tokio::test]
async fn a_slug_mismatch_is_refused() {
    let (pg, conn) = bootstrapped().await;
    let cfg = config(&pg, &[("SYSTEM_TENANT_SLUG", "config")]);

    let err = format!(
        "{:#}",
        db::migrate_and_reconcile(&conn, &cfg).await.unwrap_err()
    );
    assert!(
        err.contains("`system`") && err.contains("`config`"),
        "{err}"
    );
    assert!(err.contains("SYSTEM_TENANT_RENAME=1"), "{err}");
    let err = format!(
        "{:#}",
        bootstrap::run(&conn, &cfg, &opts()).await.unwrap_err()
    );
    assert!(err.contains("SYSTEM_TENANT_RENAME=1"), "{err}");
    assert_eq!(system(&conn).await.slug, "system");
    assert_eq!(renames(&conn).await, 0);
}

#[tokio::test]
async fn rename_with_the_flag_moves_the_system_tenant() {
    let (pg, conn) = bootstrapped().await;
    let cfg = config(
        &pg,
        &[
            ("SYSTEM_TENANT_SLUG", "config"),
            ("SYSTEM_TENANT_RENAME", "1"),
        ],
    );

    db::migrate_and_reconcile(&conn, &cfg).await.unwrap();
    let tenant = system(&conn).await;
    assert_eq!(tenant.slug, "config");
    assert_eq!(
        admin_portal_redirects(&conn, tenant.id).await,
        ["https://config.id.example.test/admin/callback"]
    );
    let event = audit_events::Entity::find()
        .filter(audit_events::Column::EventType.eq("tenant.rename"))
        .one(&conn)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.tenant_id, tenant.id);
    assert_eq!(event.target_id, Some(tenant.id));
    assert_eq!(event.details["from"], "system");
    assert_eq!(event.details["to"], "config");
    // The old host no longer serves it; the new one does.
    assert_eq!(
        apex_redirect(&conn, &cfg).await.as_deref(),
        Some("https://config.id.example.test/admin")
    );
    let state = AppState::new(conn.clone(), cfg.clone(), true);
    let router = app::router(state, common::no_web_dist());
    let discovery = "/.well-known/openid-configuration";
    let (status, _) = common::get(&router, &common::at("system", discovery)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = common::get(&router, &common::at("config", discovery)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("\"issuer\":\"https://config.id.example.test\""),
        "{body}"
    );

    // Idempotent (the flag may stay set): nothing more is renamed or audited.
    db::migrate_and_reconcile(&conn, &cfg).await.unwrap();
    bootstrap::run(&conn, &cfg, &opts()).await.unwrap();
    assert_eq!(renames(&conn).await, 1);
}

#[tokio::test]
async fn rename_onto_another_tenants_slug_is_refused() {
    let (pg, conn) = bootstrapped().await;
    let default = config(&pg, &[]);
    let new = NewTenant {
        slug: "config",
        display_name: "Config Inc",
    };
    directory::create_tenant(&conn, &default, new)
        .await
        .unwrap();
    let cfg = config(
        &pg,
        &[
            ("SYSTEM_TENANT_SLUG", "config"),
            ("SYSTEM_TENANT_RENAME", "1"),
        ],
    );

    let err = format!(
        "{:#}",
        db::migrate_and_reconcile(&conn, &cfg).await.unwrap_err()
    );
    assert!(
        err.contains("another tenant already has that slug"),
        "{err}"
    );
    assert_eq!(system(&conn).await.slug, "system");
    assert_eq!(renames(&conn).await, 0);
}
