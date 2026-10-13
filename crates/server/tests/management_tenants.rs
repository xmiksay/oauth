// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Tenant management (`/api/v1/tenants`) by Global Admins of the system
//! tenant, and a tenant settings endpoint for its own admins.
mod common;

use axum::http::{Method, StatusCode};
use common::{
    flow::Fixture,
    mgmt::{call, mint_user_token, user_with_roles},
};
use entity::{
    audit_events,
    enums::DirectoryRole::{GlobalAdmin, UserAdmin},
};
use oauth_server::{
    bootstrap,
    directory::{self, password},
};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde_json::{Value, json};

#[tokio::test]
async fn system_admins_manage_tenants() {
    let f = Fixture::new().await;
    let opts = bootstrap::Options {
        admin_email: "root@example.com".into(),
        display_name: None,
        reset_password: false,
    };
    bootstrap::run(&f.db, &f.config, &opts).await.unwrap();
    let system = directory::find_system_tenant(&f.db).await.unwrap().unwrap();
    let root = directory::find_user_by_email(&f.db, system.id, "root@example.com")
        .await
        .unwrap()
        .unwrap();
    let token = mint_user_token(&f.db, &f.config, &system, &root).await;

    let body = json!({ "slug": "fabrikam", "display_name": "Fabrikam", "admin_email": "boss@fabrikam.example" });
    let (st, created) = call(
        &f.app,
        Method::POST,
        "/api/v1/tenants",
        Some(&token),
        Some(&body),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    assert_eq!(created["admin"]["email"], "boss@fabrikam.example");
    let otp = created["one_time_password"].as_str().unwrap();
    let fabrikam = directory::find_tenant_by_slug(&f.db, "fabrikam")
        .await
        .unwrap()
        .unwrap();
    let boss = directory::find_user_by_email(&f.db, fabrikam.id, "boss@fabrikam.example")
        .await
        .unwrap()
        .unwrap();
    assert!(boss.must_change_password);
    assert!(
        password::verify(otp, boss.password_hash.as_deref().unwrap())
            .await
            .unwrap()
    );
    // The new admin can manage the new tenant right away.
    let boss_token = mint_user_token(&f.db, &f.config, &fabrikam, &boss).await;
    let (st, _) = call(
        &f.app,
        Method::GET,
        "/api/v1/tenants/fabrikam/users",
        Some(&boss_token),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    for (body, expected) in [
        (
            json!({ "slug": "fabrikam", "display_name": "Dup", "admin_email": "a@b.c" }),
            StatusCode::CONFLICT,
        ),
        (
            json!({ "slug": "api", "display_name": "Reserved", "admin_email": "a@b.c" }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "slug": "ok-slug", "display_name": "X", "admin_email": "nope" }),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let (st, _) = call(
            &f.app,
            Method::POST,
            "/api/v1/tenants",
            Some(&token),
            Some(&body),
        )
        .await;
        assert_eq!(st, expected, "{body}");
    }
    let (_, list) = call(
        &f.app,
        Method::GET,
        "/api/v1/tenants?limit=2",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(list["items"].as_array().unwrap().len(), 2);
    let cursor = list["next_cursor"].as_str().unwrap();
    let (_, rest) = call(
        &f.app,
        Method::GET,
        &format!("/api/v1/tenants?limit=2&cursor={cursor}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(
        rest["items"].as_array().unwrap().len(),
        1,
        "system, contoso, fabrikam"
    );
    assert_eq!(rest["next_cursor"], Value::Null);

    // The system tenant can't be disabled; others can (and then vanish).
    let off = json!({ "disabled": true });
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        "/api/v1/tenants/system",
        Some(&token),
        Some(&off),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, body) = call(
        &f.app,
        Method::PATCH,
        "/api/v1/tenants/fabrikam",
        Some(&token),
        Some(&off),
    )
    .await;
    assert_eq!(
        (st, body["disabled"].as_bool()),
        (StatusCode::OK, Some(true))
    );
    let (st, _) = common::get(&f.app, "/fabrikam/.well-known/openid-configuration").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = call(
        &f.app,
        Method::GET,
        "/api/v1/tenants/fabrikam/users",
        Some(&boss_token),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, body) = call(
        &f.app,
        Method::GET,
        "/api/v1/tenants/fabrikam",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(
        (st, body["disabled"].as_bool()),
        (StatusCode::OK, Some(true))
    );

    // Others: a system member without GlobalAdmin, and contoso's admin.
    let member = user_with_roles(&f.db, system.id, "member@example.com", &[UserAdmin]).await;
    let member_token = mint_user_token(&f.db, &f.config, &system, &member).await;
    let again = json!({ "slug": "other", "display_name": "Other", "admin_email": "a@b.c" });
    let (st, _) = call(
        &f.app,
        Method::POST,
        "/api/v1/tenants",
        Some(&member_token),
        Some(&again),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let contoso_token = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let (st, _) = call(
        &f.app,
        Method::GET,
        "/api/v1/tenants",
        Some(&contoso_token),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let creates = audit_events::Entity::find()
        .filter(audit_events::Column::TenantId.eq(system.id))
        .filter(audit_events::Column::EventType.eq("tenant.create"))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(creates, 1);
    // Disabling fabrikam is logged in the system tenant AND in fabrikam's
    // own log.
    for tenant_id in [system.id, fabrikam.id] {
        let updates = audit_events::Entity::find()
            .filter(audit_events::Column::TenantId.eq(tenant_id))
            .filter(audit_events::Column::EventType.eq("tenant.update"))
            .filter(audit_events::Column::TargetId.eq(fabrikam.id))
            .count(&f.db)
            .await
            .unwrap();
        assert_eq!(updates, 1, "{tenant_id}");
    }
}

#[tokio::test]
async fn tenant_admins_manage_their_own_settings() {
    let f = Fixture::new().await;
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ua = user_with_roles(&f.db, f.tenant.id, "ua@example.com", &[UserAdmin]).await;
    let ga = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let ua = mint_user_token(&f.db, &f.config, &f.tenant, &ua).await;
    let path = "/api/v1/tenants/contoso/settings";

    let (st, settings) = call(&f.app, Method::GET, path, Some(&ua), None).await;
    assert_eq!(
        (st, settings["audit_retention_days"].as_i64()),
        (StatusCode::OK, Some(90))
    );
    let change = json!({ "display_name": "Contoso Ltd", "audit_retention_days": 30 });
    let (st, _) = call(&f.app, Method::PATCH, path, Some(&ua), Some(&change)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, updated) = call(&f.app, Method::PATCH, path, Some(&ga), Some(&change)).await;
    assert_eq!(st, StatusCode::OK, "{updated}");
    assert_eq!(
        (
            updated["display_name"].as_str(),
            updated["audit_retention_days"].as_i64()
        ),
        (Some("Contoso Ltd"), Some(30))
    );
    // Enabling / disabling stays with the system tenant's admins.
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        path,
        Some(&ga),
        Some(&json!({ "disabled": true })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        path,
        Some(&ga),
        Some(&json!({ "audit_retention_days": 29 })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let logged = audit_events::Entity::find()
        .filter(audit_events::Column::TenantId.eq(f.tenant.id))
        .filter(audit_events::Column::EventType.eq("tenant.update"))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(logged, 1);
}
