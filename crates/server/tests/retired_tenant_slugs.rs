// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! A regular tenant that holds a retired system tenant slug (created before
//! retirement existed): startup refuses it enabled, tenancy never serves it
//! and it can't be re-enabled.
mod common;

use axum::http::{Method, StatusCode};
use entity::{retired_tenant_slugs, tenants};
use oauth_server::{
    app::{self, AppState},
    bootstrap::{self, Options},
    db,
    directory::{self, NewTenant},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, IntoActiveModel};
use serde_json::json;

use common::PUBLIC_URL;

#[tokio::test]
async fn a_regular_tenant_on_a_retired_slug_is_refused() {
    let pg = common::start_postgres().await;
    let conn = db::connect(&pg.url).await.unwrap();
    let cfg = common::config_with(&pg.url, PUBLIC_URL, &[]).unwrap();
    let opts = Options {
        admin_email: "root@example.com".into(),
        display_name: None,
        reset_password: false,
    };
    bootstrap::run(&conn, &cfg, &opts).await.unwrap();
    let system = directory::find_system_tenant(&conn).await.unwrap().unwrap();
    let new = NewTenant {
        slug: "legacy",
        display_name: "Legacy",
    };
    let legacy = directory::create_tenant(&conn, &cfg, new).await.unwrap();
    // As if the system tenant had lived on `legacy` before retirement existed.
    retired_tenant_slugs::Entity::insert(retired_tenant_slugs::ActiveModel {
        slug: Set("legacy".into()),
        tenant_id: Set(system.id),
        ..Default::default()
    })
    .exec(&conn)
    .await
    .unwrap();

    let err = format!(
        "{:#}",
        db::migrate_and_reconcile(&conn, &cfg).await.unwrap_err()
    );
    assert!(err.contains("legacy"), "{err}");

    let router = app::router(
        AppState::new(conn.clone(), cfg.clone(), true),
        common::no_web_dist(),
    );
    let discovery = "/.well-known/openid-configuration";
    let (status, _) = common::get(&router, &common::at("legacy", discovery)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = common::get(&router, &common::at("system", discovery)).await;
    assert_eq!(status, StatusCode::OK);

    // Disabled, it no longer blocks startup, and it can't be re-enabled.
    let mut row: tenants::ActiveModel = legacy.into_active_model();
    row.disabled = Set(true);
    row.update(&conn).await.unwrap();
    db::migrate_and_reconcile(&conn, &cfg).await.unwrap();
    let root = directory::find_user_by_email(&conn, system.id, "root@example.com")
        .await
        .unwrap()
        .unwrap();
    let token = common::mgmt::mint_user_token(&conn, &cfg, &system, &root).await;
    let url = common::at("system", "/api/v1/tenants/legacy");
    let body = json!({ "disabled": false });
    let (status, resp) =
        common::mgmt::call(&router, Method::PATCH, &url, Some(&token), Some(&body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert!(resp.to_string().contains("reserved"), "{resp}");
    let stored = directory::find_tenant_by_slug(&conn, "legacy")
        .await
        .unwrap()
        .unwrap();
    assert!(stored.disabled);
}
