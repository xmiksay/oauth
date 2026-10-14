// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Tenant management (`/api/v1/tenants` on the system host) by Global
//! Admins of the system tenant, and a tenant settings endpoint for its own
//! admins.
mod common;

fn sys(path: &str) -> String {
    common::at("system", path)
}

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
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter};
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
        &sys("/api/v1/tenants"),
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
        &common::at("fabrikam", "/api/v1/users"),
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
            &sys("/api/v1/tenants"),
            Some(&token),
            Some(&body),
        )
        .await;
        assert_eq!(st, expected, "{body}");
    }
    let (_, list) = call(
        &f.app,
        Method::GET,
        &sys("/api/v1/tenants?limit=2"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(list["items"].as_array().unwrap().len(), 2);
    let cursor = list["next_cursor"].as_str().unwrap();
    let (_, rest) = call(
        &f.app,
        Method::GET,
        &sys(&format!("/api/v1/tenants?limit=2&cursor={cursor}")),
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
        &sys("/api/v1/tenants/system"),
        Some(&token),
        Some(&off),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, body) = call(
        &f.app,
        Method::PATCH,
        &sys("/api/v1/tenants/fabrikam"),
        Some(&token),
        Some(&off),
    )
    .await;
    assert_eq!(
        (st, body["disabled"].as_bool()),
        (StatusCode::OK, Some(true))
    );
    let (st, _) = common::get(
        &f.app,
        &common::at("fabrikam", "/.well-known/openid-configuration"),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = call(
        &f.app,
        Method::GET,
        &common::at("fabrikam", "/api/v1/users"),
        Some(&boss_token),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, body) = call(
        &f.app,
        Method::GET,
        &sys("/api/v1/tenants/fabrikam"),
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
        &sys("/api/v1/tenants"),
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
        &sys("/api/v1/tenants"),
        Some(&contoso_token),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    // On any other host the tenants resource does not exist at all.
    for token in [&contoso_token, &token] {
        let (st, _) = call(&f.app, Method::GET, "/api/v1/tenants", Some(token), None).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }
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
async fn a_tenant_whose_slug_is_now_invalid_cannot_be_re_enabled() {
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
    // An M1a-era tenant, disabled so the server could start.
    f.db.execute_unprepared(
        "INSERT INTO tenants (id, slug, display_name, disabled) \
         VALUES (gen_random_uuid(), 'www', 'W', true)",
    )
    .await
    .unwrap();
    let www = directory::find_tenant_by_slug(&f.db, "www")
        .await
        .unwrap()
        .unwrap();

    let enable = json!({ "disabled": false });
    let (st, body) = call(
        &f.app,
        Method::PATCH,
        &sys("/api/v1/tenants/www"),
        Some(&token),
        Some(&enable),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("can't be re-enabled"),
        "{body}"
    );
    let after = directory::find_tenant_by_slug(&f.db, "www")
        .await
        .unwrap()
        .unwrap();
    assert!(after.disabled);
    assert_eq!(after.updated_at, www.updated_at);
    let audited = audit_events::Entity::find()
        .filter(audit_events::Column::TargetId.eq(www.id))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(audited, 0);
    // Combined with a rename: still refused as a whole, nothing written.
    let both = json!({ "display_name": "Renamed", "disabled": false });
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        &sys("/api/v1/tenants/www"),
        Some(&token),
        Some(&both),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let after = directory::find_tenant_by_slug(&f.db, "www")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((after.display_name.as_str(), after.disabled), ("W", true));
    let audited = audit_events::Entity::find()
        .filter(audit_events::Column::TargetId.eq(www.id))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(audited, 0);
    // `system` is reserved, but the system tenant itself is exempt; an unknown
    // slug is still 404.
    for (path, expected) in [
        ("/api/v1/tenants/system", StatusCode::OK),
        ("/api/v1/tenants/nope", StatusCode::NOT_FOUND),
    ] {
        let (st, body) = call(
            &f.app,
            Method::PATCH,
            &sys(path),
            Some(&token),
            Some(&enable),
        )
        .await;
        assert_eq!(st, expected, "{path}: {body}");
    }
    // Other edits of it still work.
    let rename = json!({ "display_name": "Old www" });
    let (st, _) = call(
        &f.app,
        Method::PATCH,
        &sys("/api/v1/tenants/www"),
        Some(&token),
        Some(&rename),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn tenant_admins_manage_their_own_settings() {
    let f = Fixture::new().await;
    let ga = user_with_roles(&f.db, f.tenant.id, "ga@example.com", &[GlobalAdmin]).await;
    let ua = user_with_roles(&f.db, f.tenant.id, "ua@example.com", &[UserAdmin]).await;
    let ga = mint_user_token(&f.db, &f.config, &f.tenant, &ga).await;
    let ua = mint_user_token(&f.db, &f.config, &f.tenant, &ua).await;
    let path = "/api/v1/settings";

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
