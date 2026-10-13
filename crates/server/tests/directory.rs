// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use entity::{
    app_required_permissions, app_roles, app_scopes, applications, consent_grants,
    directory_role_assignments,
    enums::{ClientType, DirectoryRole, KeyStatus, SigningAlg},
    group_members, groups, signing_keys, tenants, users,
};
use jsonwebtoken::{DecodingKey, Validation, jwk::JwkSet};
use oauth_server::{
    directory::{
        self, DirectoryError, NewTenant, NewUser,
        builtin_apps::{ADMIN_PORTAL, MANAGEMENT_API, MY_ACCOUNT, SCOPE_ACCESS_AS_USER},
        password,
    },
    keys,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter,
};
use serde_json::json;
use uuid::Uuid;

async fn tenant(
    conn: &DatabaseConnection,
    config: &oauth_server::config::Config,
    slug: &str,
) -> tenants::Model {
    directory::create_tenant(
        conn,
        config,
        NewTenant {
            slug,
            display_name: slug,
        },
    )
    .await
    .unwrap()
}

fn new_user(email: &str) -> NewUser<'_> {
    NewUser {
        email,
        display_name: "Ann",
        password: None,
        must_change_password: false,
    }
}

#[tokio::test]
async fn create_tenant_provisions_keys_builtin_apps_and_consent() {
    let (_pg, conn, config) = common::migrated_db().await;
    let t = tenant(&conn, &config, "contoso").await;
    assert!(!t.is_system && !t.disabled);
    assert_eq!(t.audit_retention_days, 90);

    // Keys: one active per alg; each signs tokens its JWKS entry verifies.
    let jwks: JwkSet = serde_json::from_value(keys::jwks(&conn, t.id).await.unwrap()).unwrap();
    assert_eq!(jwks.keys.len(), 2);
    for alg in [SigningAlg::Rs256, SigningAlg::Es256] {
        let key = keys::active_signing_key(&conn, &config.master_key, t.id, alg)
            .await
            .unwrap();
        let token = jsonwebtoken::encode(
            &key.header(),
            &json!({"exp": 4_000_000_000u64}),
            &key.encoding_key,
        )
        .unwrap();
        let jwk = jwks.find(&key.kid).expect("active key in JWKS");
        jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &DecodingKey::from_jwk(jwk).unwrap(),
            &Validation::new(keys::jwt_algorithm(alg)),
        )
        .unwrap();
    }

    let apps = applications::Entity::find()
        .filter(applications::Column::TenantId.eq(t.id))
        .all(&conn)
        .await
        .unwrap();
    assert_eq!(apps.len(), 3);
    assert!(apps.iter().all(|a| a.builtin));
    let app = |client_id: &str| apps.iter().find(|a| a.client_id == client_id).unwrap();

    let api = app(MANAGEMENT_API);
    assert_eq!(api.identifier_uri.as_deref(), Some("api://management-api"));
    let scopes = app_scopes::Entity::find()
        .filter(app_scopes::Column::ApplicationId.eq(api.id))
        .all(&conn)
        .await
        .unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].value, SCOPE_ACCESS_AS_USER);
    assert!(scopes[0].admin_consent_required);
    let mut roles: Vec<_> = app_roles::Entity::find()
        .filter(app_roles::Column::ApplicationId.eq(api.id))
        .all(&conn)
        .await
        .unwrap();
    roles.sort_by(|a, b| a.value.cmp(&b.value));
    let values: Vec<_> = roles.iter().map(|r| r.value.as_str()).collect();
    assert_eq!(values, ["Directory.Read.All", "Directory.ReadWrite.All"]);
    assert!(
        roles
            .iter()
            .all(|r| r.allowed_member_types == ["application"])
    );

    for (client_id, area) in [(ADMIN_PORTAL, "admin"), (MY_ACCOUNT, "myaccount")] {
        let spa = app(client_id);
        assert_eq!(spa.client_type, ClientType::Public);
        let base = format!("{}/contoso/{area}", common::PUBLIC_URL);
        assert_eq!(spa.redirect_uris, [format!("{base}/callback")]);
        assert_eq!(spa.post_logout_redirect_uris, [base]);

        let perms = app_required_permissions::Entity::find()
            .filter(app_required_permissions::Column::ApplicationId.eq(spa.id))
            .all(&conn)
            .await
            .unwrap();
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0].resource_application_id, api.id);
        assert_eq!(perms[0].scope_id, Some(scopes[0].id));

        let consent = consent_grants::Entity::find()
            .filter(consent_grants::Column::ClientApplicationId.eq(spa.id))
            .one(&conn)
            .await
            .unwrap()
            .expect("admin consent");
        assert_eq!(consent.user_id, None, "must be tenant-wide admin consent");
        assert_eq!(consent.resource_application_id, api.id);
        assert_eq!(consent.scopes, [SCOPE_ACCESS_AS_USER]);
    }
}

#[tokio::test]
async fn duplicate_or_reserved_slug_is_rejected_without_partial_rows() {
    let (_pg, conn, config) = common::migrated_db().await;
    tenant(&conn, &config, "contoso").await;

    let dup = directory::create_tenant(
        &conn,
        &config,
        NewTenant {
            slug: "contoso",
            display_name: "Again",
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(dup, DirectoryError::SlugTaken(ref s) if s == "contoso"),
        "{dup:?}"
    );
    for slug in ["api", "system", "Bad Slug"] {
        let err = directory::create_tenant(
            &conn,
            &config,
            NewTenant {
                slug,
                display_name: "x",
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DirectoryError::Invalid(_)), "{slug}: {err:?}");
    }

    // The failed transaction left nothing behind.
    assert_eq!(tenants::Entity::find().count(&conn).await.unwrap(), 1);
    assert_eq!(signing_keys::Entity::find().count(&conn).await.unwrap(), 2);
    assert_eq!(applications::Entity::find().count(&conn).await.unwrap(), 3);
}

#[tokio::test]
async fn user_email_is_unique_per_tenant_case_insensitively() {
    let (_pg, conn, config) = common::migrated_db().await;
    let a = tenant(&conn, &config, "tenant-a").await;
    let b = tenant(&conn, &config, "tenant-b").await;

    let ann = directory::create_user(&conn, a.id, new_user("Ann@Example.com"))
        .await
        .unwrap();
    let dup = directory::create_user(&conn, a.id, new_user("ann@EXAMPLE.com"))
        .await
        .unwrap_err();
    assert!(matches!(dup, DirectoryError::EmailTaken(_)), "{dup:?}");
    // Same address in another tenant is a different identity.
    let ann_b = directory::create_user(&conn, b.id, new_user("ann@example.com"))
        .await
        .unwrap();
    assert_ne!(ann.id, ann_b.id);

    let found = directory::find_user_by_email(&conn, a.id, " ANN@example.COM ")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.id, ann.id);
    assert_eq!(found.email, "Ann@Example.com", "original casing is kept");
    assert!(found.password_hash.is_none());

    // Non-ASCII case variants: the unique index and the lookup both use
    // Postgres lower(), so they agree (the test image runs en_US.utf8).
    let zofie = directory::create_user(&conn, a.id, new_user("Žofie@Příklad.cz"))
        .await
        .unwrap();
    let dup = directory::create_user(&conn, a.id, new_user("žofie@příklad.CZ"))
        .await
        .unwrap_err();
    assert!(matches!(dup, DirectoryError::EmailTaken(_)), "{dup:?}");
    let found = directory::find_user_by_email(&conn, a.id, "ŽOFIE@PŘÍKLAD.cz")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.id, zofie.id);
    let nul = directory::find_user_by_email(&conn, a.id, "ann\0@example.com")
        .await
        .unwrap();
    assert!(nul.is_none());

    let unknown_tenant = directory::create_user(&conn, Uuid::now_v7(), new_user("x@example.com"))
        .await
        .unwrap_err();
    assert!(
        matches!(unknown_tenant, DirectoryError::NotFound),
        "{unknown_tenant:?}"
    );
}

#[tokio::test]
async fn passwords_and_directory_roles() {
    let (_pg, conn, config) = common::migrated_db().await;
    let a = tenant(&conn, &config, "tenant-a").await;
    let b = tenant(&conn, &config, "tenant-b").await;
    let user = directory::create_user(&conn, a.id, new_user("ann@example.com"))
        .await
        .unwrap();

    directory::set_password(&conn, a.id, user.id, "a long enough pw", true)
        .await
        .unwrap();
    let stored = users::Entity::find_by_id(user.id)
        .one(&conn)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.must_change_password);
    let hash = stored.password_hash.unwrap();
    assert!(password::verify("a long enough pw", &hash).await.unwrap());
    let short = directory::set_password(&conn, a.id, user.id, "short", false)
        .await
        .unwrap_err();
    assert!(matches!(short, DirectoryError::Invalid(_)));
    // Wrong tenant: the user isn't visible there.
    let cross = directory::set_password(&conn, b.id, user.id, "a long enough pw", false)
        .await
        .unwrap_err();
    assert!(matches!(cross, DirectoryError::NotFound), "{cross:?}");

    for _ in 0..2 {
        directory::assign_directory_role(&conn, a.id, user.id, DirectoryRole::UserAdmin)
            .await
            .unwrap();
    }
    let count = directory_role_assignments::Entity::find()
        .filter(directory_role_assignments::Column::UserId.eq(user.id))
        .count(&conn)
        .await
        .unwrap();
    assert_eq!(count, 1, "assignment must be idempotent");
    let cross = directory::assign_directory_role(&conn, b.id, user.id, DirectoryRole::GlobalAdmin)
        .await
        .unwrap_err();
    assert!(matches!(cross, DirectoryError::NotFound), "{cross:?}");
}

#[tokio::test]
async fn schema_refuses_cross_tenant_links() {
    let (_pg, conn, config) = common::migrated_db().await;
    let a = tenant(&conn, &config, "tenant-a").await;
    let b = tenant(&conn, &config, "tenant-b").await;
    let user_b = directory::create_user(&conn, b.id, new_user("bob@example.com"))
        .await
        .unwrap();
    let group_a = groups::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(a.id),
        display_name: Set("Admins".into()),
        description: Set(None),
        ..Default::default()
    }
    .insert(&conn)
    .await
    .unwrap();

    for tenant_id in [a.id, b.id] {
        let member = group_members::ActiveModel {
            tenant_id: Set(tenant_id),
            group_id: Set(group_a.id),
            user_id: Set(user_b.id),
            ..Default::default()
        };
        assert!(
            member.insert(&conn).await.is_err(),
            "cross-tenant membership accepted"
        );
    }
}

#[tokio::test]
async fn jwks_publishes_next_and_unexpired_retired_keys() {
    let (_pg, conn, config) = common::migrated_db().await;
    let t = tenant(&conn, &config, "contoso").await;
    let now = chrono::Utc::now().fixed_offset();

    // Retired keys are staged as `next` and then retired (the CHECK requires
    // retirement timestamps), before the real `next` key — one `next` per alg.
    for (alg, expires_at) in [
        (SigningAlg::Rs256, now + chrono::Duration::hours(1)),
        (SigningAlg::Es256, now - chrono::Duration::hours(1)),
    ] {
        let key = keys::generate(alg).await.unwrap();
        let row = keys::insert(&conn, &config.master_key, t.id, &key, KeyStatus::Next)
            .await
            .unwrap();
        let mut row: signing_keys::ActiveModel = row.into();
        row.status = Set(KeyStatus::Retired);
        row.retired_at = Set(Some(now));
        row.expires_at = Set(Some(expires_at));
        row.update(&conn).await.unwrap();
    }
    let next = keys::generate(SigningAlg::Rs256).await.unwrap();
    keys::insert(&conn, &config.master_key, t.id, &next, KeyStatus::Next)
        .await
        .unwrap();

    let jwks: JwkSet = serde_json::from_value(keys::jwks(&conn, t.id).await.unwrap()).unwrap();
    // 2 active + 1 next + 1 retired-but-unexpired; the expired one is gone.
    assert_eq!(jwks.keys.len(), 4);
    assert!(jwks.find(&next.kid).is_some());
}
