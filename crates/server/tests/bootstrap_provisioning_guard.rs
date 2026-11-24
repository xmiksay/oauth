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
    bootstrap::{self, Options, TenantOptions, provisioning, takeover::Takeover},
    directory::builtin_apps::{ROLE_READ_ALL, ROLE_READ_WRITE_ALL},
};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde_json::json;

fn opts(adopt: bool, rotate: bool) -> Options {
    opts_with(provisioning::Role::ReadWrite, adopt, rotate)
}

fn opts_with(role: provisioning::Role, adopt: bool, rotate: bool) -> Options {
    Options {
        tenant: Some(TenantOptions {
            slug: "contoso".into(),
            display_name: None,
        }),
        provisioning: Some(provisioning::Options {
            client_id: "audit-export".into(),
            role,
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

async fn secret_count(f: &Fixture, app: uuid::Uuid) -> u64 {
    client_secrets::Entity::find()
        .filter(client_secrets::Column::ApplicationId.eq(app))
        .count(&f.db)
        .await
        .unwrap()
}

/// A third-party app `audit-export` a Global Admin gave `role` through the API.
async fn siem_holding(f: &Fixture, role: &str) -> uuid::Uuid {
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
    let role = roles["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["value"] == role)
        .unwrap()["id"]
        .clone();
    let assign =
        json!({ "app_role_id": role, "principal_type": "application", "principal_id": siem.id });
    let (st, _) = post(f, &ga, "/api/v1/role-assignments", assign).await;
    assert_eq!(st, StatusCode::CREATED);
    siem.id
}

#[tokio::test]
async fn an_admin_assigned_read_role_is_not_upgraded_without_adopt() {
    let f = Fixture::new().await;
    let siem = siem_holding(&f, ROLE_READ_ALL).await;

    // The default role (read-write) is refused, before any write.
    let err = bootstrap::run(&f.db, &f.config, &opts(false, true))
        .await
        .unwrap_err();
    let err = format!("{err:#}");
    assert!(
        err.contains("--adopt-app") && err.contains(ROLE_READ_ALL),
        "{err}"
    );
    assert_eq!(held_roles(&f, siem).await, [ROLE_READ_ALL]);
    assert_eq!(secret_count(&f, siem).await, 0);

    // With the flag it is upgraded, loudly.
    let report = bootstrap::run(&f.db, &f.config, &opts(true, false))
        .await
        .unwrap();
    let text = report.render();
    for line in [
        "WARNING: upgraded existing app `audit-export` from Directory.Read.All \
         to Directory.ReadWrite.All (--adopt-app).",
        "WARNING: Assigned management API role Directory.ReadWrite.All to `audit-export`.",
        "WARNING: Removed management API role Directory.Read.All from `audit-export`.",
    ] {
        assert!(text.contains(line), "{text}");
    }
    assert_eq!(held_roles(&f, siem).await, [ROLE_READ_WRITE_ALL]);

    // Now it holds read-write: re-runs keep it without the flag.
    let p = bootstrap::run(&f.db, &f.config, &opts(false, false))
        .await
        .unwrap()
        .provisioning
        .unwrap();
    assert!(p.adopted.is_none() && !p.role_assigned && p.role_removed.is_none());
}

#[tokio::test]
async fn a_secret_for_an_app_bootstrap_did_not_make_needs_adopt() {
    let f = Fixture::new().await;
    let siem = siem_holding(&f, ROLE_READ_ALL).await;
    let read = |adopt| opts_with(provisioning::Role::Read, adopt, true);

    // Holding the requested role is no proof bootstrap made the app.
    let err = bootstrap::run(&f.db, &f.config, &read(false))
        .await
        .unwrap_err();
    let err = format!("{err:#}");
    assert!(
        err.contains("--adopt-app") && err.contains("new secret"),
        "{err}"
    );
    assert_eq!(secret_count(&f, siem).await, 0);
    // Without --rotate-secret nothing changes, so nothing is asked.
    let p = bootstrap::run(
        &f.db,
        &f.config,
        &opts_with(provisioning::Role::Read, false, false),
    )
    .await
    .unwrap()
    .provisioning
    .unwrap();
    assert!(p.adopted.is_none() && p.secret.is_none());

    let report = bootstrap::run(&f.db, &f.config, &read(true)).await.unwrap();
    assert!(
        report
            .render()
            .contains("WARNING: issuing a secret for existing app `audit-export`")
    );
    let p = report.provisioning.unwrap();
    assert_eq!(p.adopted, Some(Takeover::RotateSecret));
    assert!(p.secret.is_some());
    assert_eq!(held_roles(&f, siem).await, [ROLE_READ_ALL]);

    // Its bootstrap secret now marks it: rotating again needs no flag.
    let p = bootstrap::run(&f.db, &f.config, &read(false))
        .await
        .unwrap()
        .provisioning
        .unwrap();
    assert!(p.adopted.is_none() && p.secret.is_some());
    assert_eq!(secret_count(&f, siem).await, 2);
}

#[tokio::test]
async fn an_admin_assigned_read_write_role_is_not_downgraded_without_adopt() {
    let f = Fixture::new().await;
    let siem = siem_holding(&f, ROLE_READ_WRITE_ALL).await;
    let read = |adopt| opts_with(provisioning::Role::Read, adopt, false);

    let err = bootstrap::run(&f.db, &f.config, &read(false))
        .await
        .unwrap_err();
    let err = format!("{err:#}");
    assert!(
        err.contains("--adopt-app") && err.contains("downgrade"),
        "{err}"
    );
    assert_eq!(held_roles(&f, siem).await, [ROLE_READ_WRITE_ALL]);
    // Neither does --rotate-secret with the role it already holds.
    let err = bootstrap::run(&f.db, &f.config, &opts(false, true))
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("new secret"), "{err:#}");
    assert_eq!(secret_count(&f, siem).await, 0);

    let report = bootstrap::run(&f.db, &f.config, &read(true)).await.unwrap();
    assert!(
        report
            .render()
            .contains("WARNING: downgraded existing app `audit-export`")
    );
    assert_eq!(
        report.provisioning.unwrap().adopted,
        Some(Takeover::Downgrade)
    );
    assert_eq!(held_roles(&f, siem).await, [ROLE_READ_ALL]);
}
