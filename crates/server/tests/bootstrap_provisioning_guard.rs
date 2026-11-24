// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `oauth bootstrap --provisioning-app` must not take for its own an app an
//! admin gave a management API role (#97): holding `Directory.Read.All` says
//! nothing about who made the app.

mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{app_by_client_id, call, mint_user_token, post, user_with_roles},
};
use entity::{
    app_role_assignments as ara, app_roles, client_secrets,
    enums::{AccessTokenFormat, ClientType, DirectoryRole, SigningAlg},
};
use oauth_server::{
    bootstrap::{self, Options, TenantOptions, provisioning},
    directory::builtin_apps::{ROLE_READ_ALL, ROLE_READ_WRITE_ALL},
};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde_json::json;

fn opts(adopt: bool, rotate: bool) -> Options {
    Options {
        tenant: Some(TenantOptions {
            slug: "contoso".into(),
            display_name: None,
        }),
        provisioning: Some(provisioning::Options {
            client_id: "audit-export".into(),
            role: provisioning::Role::ReadWrite,
            rotate_secret: rotate,
            adopt,
        }),
        ..Default::default()
    }
}

async fn held_roles(f: &Fixture, app: uuid::Uuid) -> Vec<String> {
    let ids: Vec<uuid::Uuid> = ara::Entity::find()
        .filter(ara::Column::ClientApplicationId.eq(app))
        .all(&f.db)
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.app_role_id)
        .collect();
    let mut roles: Vec<String> = app_roles::Entity::find()
        .filter(app_roles::Column::Id.is_in(ids))
        .all(&f.db)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.value)
        .collect();
    roles.sort();
    roles
}

#[tokio::test]
async fn an_admin_assigned_read_role_is_not_upgraded_without_adopt() {
    let f = Fixture::new().await;
    let siem = common::seed::add_app(
        &f.db,
        f.tenant.id,
        "audit-export",
        ClientType::Confidential,
        None,
        AccessTokenFormat::Jwt,
        SigningAlg::Rs256,
    )
    .await;
    // A Global Admin gives the third-party app read access through the API.
    let ga = user_with_roles(
        &f.db,
        f.tenant.id,
        "ga@example.com",
        &[DirectoryRole::GlobalAdmin],
    )
    .await;
    let ga = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let api = app_by_client_id(&f.db, f.tenant.id, "management-api").await;
    let (_, roles) = call(
        &f.app,
        Method::GET,
        &format!("/api/v1/applications/{}/roles", api.id),
        Some(&ga),
        None,
    )
    .await;
    let read = roles["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["value"] == ROLE_READ_ALL)
        .unwrap()["id"]
        .clone();
    let assign =
        json!({ "app_role_id": read, "principal_type": "application", "principal_id": siem.id });
    let (st, _) = post(&f, &ga, "/api/v1/role-assignments", assign).await;
    assert_eq!(st, StatusCode::CREATED);

    // The default role (read-write) is refused, before any write.
    let err = bootstrap::run(&f.db, &f.config, &opts(false, true))
        .await
        .unwrap_err();
    let err = format!("{err:#}");
    assert!(
        err.contains("--adopt-app") && err.contains(ROLE_READ_ALL),
        "{err}"
    );
    assert_eq!(held_roles(&f, siem.id).await, [ROLE_READ_ALL]);
    let secrets = client_secrets::Entity::find()
        .filter(client_secrets::Column::ApplicationId.eq(siem.id))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(secrets, 0);

    // With the flag it is upgraded, loudly.
    let report = bootstrap::run(&f.db, &f.config, &opts(true, false))
        .await
        .unwrap();
    let text = report.render();
    for line in [
        "WARNING: adopted existing app `audit-export`",
        "WARNING: Assigned management API role Directory.ReadWrite.All to `audit-export`.",
        "WARNING: Removed management API role Directory.Read.All from `audit-export`.",
    ] {
        assert!(text.contains(line), "{text}");
    }
    assert_eq!(held_roles(&f, siem.id).await, [ROLE_READ_WRITE_ALL]);

    // Now it holds read-write: re-runs keep it without the flag.
    let p = bootstrap::run(&f.db, &f.config, &opts(false, false))
        .await
        .unwrap()
        .provisioning
        .unwrap();
    assert!(!p.adopted && !p.role_assigned && p.role_removed.is_none());
}
