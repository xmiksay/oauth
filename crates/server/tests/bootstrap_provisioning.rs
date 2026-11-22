// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! `oauth bootstrap --tenant … --provisioning-app …`: a regular tenant and
//! a client-credentials app holding a management API role, no UI step.

mod common;

use axum::http::{Method, StatusCode};
use common::{flow::Fixture, mgmt::call};
use entity::{applications, audit_events, enums::ActorType, tenants};
use oauth_server::{
    bootstrap::{self, Options, TenantOptions, provisioning},
    db,
    directory::{self, builtin_apps},
};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

fn provisioning_opts(tenant: &str, role: provisioning::Role, rotate: bool) -> Options {
    Options {
        tenant: Some(TenantOptions {
            slug: tenant.into(),
            display_name: None,
        }),
        provisioning: Some(provisioning::Options {
            client_id: "ci".into(),
            role,
            rotate_secret: rotate,
        }),
        ..Default::default()
    }
}

async fn token(f: &Fixture, secret: &str) -> (StatusCode, Option<String>) {
    let form = [
        ("grant_type", "client_credentials"),
        ("scope", "api://management-api/.default"),
    ];
    let (st, _, body) = f
        .post_form("/oauth2/token", &form, Some(("ci", secret)))
        .await;
    (st, body["access_token"].as_str().map(str::to_owned))
}

#[tokio::test]
async fn provisioning_app_calls_the_api_with_its_one_time_secret() {
    let f = Fixture::new().await;
    let rw = provisioning::Role::ReadWrite;
    let first = bootstrap::run(&f.db, &f.config, &provisioning_opts("contoso", rw, false))
        .await
        .unwrap();
    assert!(!first.tenant_created);
    assert!(first.admin.is_none());
    let p = first.provisioning.unwrap();
    assert!(p.created && p.role_assigned);
    let secret = p.secret.unwrap().expose().to_owned();

    let (st, token1) = token(&f, &secret).await;
    assert_eq!(st, StatusCode::OK);
    let token1 = token1.unwrap();
    let user = serde_json::json!({ "email": "made-by-ci@example.com", "display_name": "CI" });
    let (st, _) = call(
        &f.app,
        Method::POST,
        "/api/v1/users",
        Some(&token1),
        Some(&user),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    // App roles never reach directory roles.
    let (st, _) = call(
        &f.app,
        Method::GET,
        "/api/v1/identity-providers",
        Some(&token1),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Re-run: nothing new, no secret printed.
    let again = bootstrap::run(&f.db, &f.config, &provisioning_opts("contoso", rw, false))
        .await
        .unwrap()
        .provisioning
        .unwrap();
    assert!(!again.created && !again.role_assigned && again.secret.is_none());
    assert!(
        !bootstrap::Report {
            tenant_slug: "contoso".into(),
            tenant_created: false,
            admin: None,
            provisioning: Some(again),
        }
        .render()
        .contains(&secret)
    );

    // Rotation adds a secret; the old one keeps working until removed.
    let rotated = bootstrap::run(&f.db, &f.config, &provisioning_opts("contoso", rw, true))
        .await
        .unwrap()
        .provisioning
        .unwrap()
        .secret
        .unwrap();
    assert_ne!(rotated.expose(), secret);
    assert_eq!(token(&f, rotated.expose()).await.0, StatusCode::OK);
    assert_eq!(token(&f, &secret).await.0, StatusCode::OK);

    let system_events = audit_events::Entity::find()
        .filter(audit_events::Column::TenantId.eq(f.tenant.id))
        .filter(audit_events::Column::ActorType.eq(ActorType::System))
        .count(&f.db)
        .await
        .unwrap();
    // App create, two secrets, one role assignment.
    assert_eq!(system_events, 4);
}

#[tokio::test]
async fn read_only_provisioning_app_cannot_write() {
    let f = Fixture::new().await;
    let opts = provisioning_opts("contoso", provisioning::Role::Read, false);
    let report = bootstrap::run(&f.db, &f.config, &opts).await.unwrap();
    let p = report.provisioning.unwrap();
    assert_eq!(p.role, builtin_apps::ROLE_READ_ALL);
    let token = token(&f, p.secret.unwrap().expose()).await.1.unwrap();
    let (st, _) = call(&f.app, Method::GET, "/api/v1/users", Some(&token), None).await;
    assert_eq!(st, StatusCode::OK);
    let user = serde_json::json!({ "email": "x@example.com", "display_name": "X" });
    let (st, _) = call(
        &f.app,
        Method::POST,
        "/api/v1/users",
        Some(&token),
        Some(&user),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

async fn create_user(f: &Fixture, token: &str, email: &str) -> StatusCode {
    let user = serde_json::json!({ "email": email, "display_name": "X" });
    call(
        &f.app,
        Method::POST,
        "/api/v1/users",
        Some(token),
        Some(&user),
    )
    .await
    .0
}

#[tokio::test]
async fn re_running_with_read_downgrades_the_app() {
    let f = Fixture::new().await;
    let rw = provisioning_opts("contoso", provisioning::Role::ReadWrite, false);
    let p = bootstrap::run(&f.db, &f.config, &rw)
        .await
        .unwrap()
        .provisioning
        .unwrap();
    assert_eq!(p.role_removed, None);
    let secret = p.secret.unwrap().expose().to_owned();

    let read = provisioning_opts("contoso", provisioning::Role::Read, false);
    let report = bootstrap::run(&f.db, &f.config, &read).await.unwrap();
    let text = report.render();
    let p = report.provisioning.unwrap();
    assert!(p.role_assigned);
    assert_eq!(p.role_removed, Some(builtin_apps::ROLE_READ_WRITE_ALL));
    assert!(
        text.contains("Removed management API role Directory.ReadWrite.All from `ci`"),
        "{text}"
    );
    let removed = audit_events::Entity::find()
        .filter(audit_events::Column::TenantId.eq(f.tenant.id))
        .filter(audit_events::Column::ActorType.eq(ActorType::System))
        .filter(audit_events::Column::EventType.eq("app_role_assignment.delete"))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(removed, 1);

    let bearer = token(&f, &secret).await.1.unwrap();
    let (st, _) = call(&f.app, Method::GET, "/api/v1/users", Some(&bearer), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        create_user(&f, &bearer, "x@example.com").await,
        StatusCode::FORBIDDEN
    );

    // And back up: read-write again, the read role goes.
    let p = bootstrap::run(&f.db, &f.config, &rw)
        .await
        .unwrap()
        .provisioning
        .unwrap();
    assert_eq!(p.role_removed, Some(builtin_apps::ROLE_READ_ALL));
    let bearer = token(&f, &secret).await.1.unwrap();
    assert_eq!(
        create_user(&f, &bearer, "y@example.com").await,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn bootstrap_creates_a_regular_tenant_with_its_admin() {
    let pg = common::start_postgres().await;
    let conn = db::connect(&pg.url).await.unwrap();
    let config = common::test_config(&pg.url, common::PUBLIC_URL);
    let opts = |tenant: &str| Options {
        admin_email: Some("owner@acme.example".into()),
        tenant: Some(TenantOptions {
            slug: tenant.into(),
            display_name: Some("Acme Inc.".into()),
        }),
        ..Default::default()
    };
    let report = bootstrap::run(&conn, &config, &opts("acme")).await.unwrap();
    assert!(report.tenant_created);
    assert!(report.render().contains("Created tenant `acme`"));
    let acme = directory::find_tenant_by_slug(&conn, "acme")
        .await
        .unwrap()
        .unwrap();
    assert!(!acme.is_system);
    assert_eq!(acme.display_name, "Acme Inc.");
    // Only this tenant: no `system` tenant is created on the way.
    assert_eq!(tenants::Entity::find().count(&conn).await.unwrap(), 1);
    let builtin = applications::Entity::find()
        .filter(applications::Column::TenantId.eq(acme.id))
        .filter(applications::Column::Builtin.eq(true))
        .count(&conn)
        .await
        .unwrap();
    assert_eq!(builtin, 3);
    let admin = directory::find_user_by_email(&conn, acme.id, "owner@acme.example")
        .await
        .unwrap()
        .unwrap();
    assert!(admin.must_change_password);
    let created = audit_events::Entity::find()
        .filter(audit_events::Column::TenantId.eq(acme.id))
        .filter(audit_events::Column::ActorType.eq(ActorType::System))
        .filter(audit_events::Column::EventType.eq("tenant.create"))
        .count(&conn)
        .await
        .unwrap();
    assert_eq!(created, 1);

    let again = bootstrap::run(&conn, &config, &opts("acme")).await.unwrap();
    assert!(!again.tenant_created);
    assert_eq!(
        again.admin.unwrap().outcome,
        bootstrap::AdminOutcome::Unchanged
    );

    // Reserved and malformed slugs are refused.
    for bad in ["www", "Bad_Slug"] {
        assert!(
            bootstrap::run(&conn, &config, &opts(bad)).await.is_err(),
            "{bad}"
        );
    }
    assert!(
        bootstrap::run(&conn, &config, &Options::default())
            .await
            .is_err()
    );
}
