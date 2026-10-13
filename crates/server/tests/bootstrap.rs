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
    applications, directory_role_assignments, enums::DirectoryRole, signing_keys, tenants, users,
};
use oauth_server::{
    bootstrap::{self, AdminOutcome, Options},
    db,
    directory::{self, password},
};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter};

const EMAIL: &str = "root@example.com";

fn opts(reset_password: bool) -> Options {
    Options {
        admin_email: EMAIL.into(),
        display_name: Some("Root".into()),
        reset_password,
    }
}

async fn admin(conn: &DatabaseConnection) -> users::Model {
    let system = directory::find_system_tenant(conn).await.unwrap().unwrap();
    directory::find_user_by_email(conn, system.id, EMAIL)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn bootstrap_is_idempotent_and_resets_only_on_request() {
    // Unmigrated database: bootstrap migrates by itself.
    let pg = common::start_postgres().await;
    let conn = db::connect(&pg.url).await.unwrap();
    let config = common::test_config(&pg.url);

    let first = bootstrap::run(&conn, &config, &opts(false)).await.unwrap();
    assert!(first.tenant_created);
    let AdminOutcome::Created { password: pw1 } = &first.admin else {
        panic!("expected Created, got {:?}", first.admin);
    };
    assert!(first.render().contains(pw1.expose()));

    let system = directory::find_system_tenant(&conn).await.unwrap().unwrap();
    assert_eq!(system.slug, "system");
    assert!(system.is_system);
    // The system tenant is provisioned like any other.
    let apps = applications::Entity::find()
        .filter(applications::Column::TenantId.eq(system.id))
        .count(&conn)
        .await
        .unwrap();
    assert_eq!(apps, 3);
    let keys = signing_keys::Entity::find()
        .filter(signing_keys::Column::TenantId.eq(system.id))
        .count(&conn)
        .await
        .unwrap();
    assert_eq!(keys, 2);

    let user = admin(&conn).await;
    assert_eq!(user.display_name, "Root");
    assert!(user.must_change_password);
    let hash1 = user.password_hash.clone().unwrap();
    assert!(password::verify(pw1.expose(), &hash1).await.unwrap());
    let roles: Vec<_> = directory_role_assignments::Entity::find()
        .filter(directory_role_assignments::Column::UserId.eq(user.id))
        .all(&conn)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.role)
        .collect();
    assert_eq!(roles, [DirectoryRole::GlobalAdmin]);

    // Second run: nothing changes, no password printed.
    let second = bootstrap::run(&conn, &config, &opts(false)).await.unwrap();
    assert!(!second.tenant_created);
    assert_eq!(second.admin, AdminOutcome::Unchanged);
    assert!(!second.render().contains(pw1.expose()));
    assert_eq!(admin(&conn).await.password_hash.unwrap(), hash1);
    assert_eq!(tenants::Entity::find().count(&conn).await.unwrap(), 1);

    // --reset-password issues a new one-time password.
    let third = bootstrap::run(&conn, &config, &opts(true)).await.unwrap();
    let AdminOutcome::PasswordReset { password: pw2 } = &third.admin else {
        panic!("expected PasswordReset, got {:?}", third.admin);
    };
    assert_ne!(pw1, pw2);
    let user = admin(&conn).await;
    let hash2 = user.password_hash.unwrap();
    assert!(password::verify(pw2.expose(), &hash2).await.unwrap());
    assert!(!password::verify(pw1.expose(), &hash2).await.unwrap());
    assert!(user.must_change_password);
}

#[tokio::test]
async fn concurrent_bootstraps_create_one_admin() {
    let pg = common::start_postgres().await;
    let conn = db::connect(&pg.url).await.unwrap();
    let config = common::test_config(&pg.url);

    let run = || {
        let (conn, config) = (conn.clone(), config.clone());
        tokio::spawn(async move { bootstrap::run(&conn, &config, &opts(false)).await })
    };
    let (a, b) = tokio::join!(run(), run());
    let mut outcomes = [a.unwrap().unwrap().admin, b.unwrap().unwrap().admin];
    outcomes.sort_by_key(|o| matches!(o, AdminOutcome::Unchanged));
    assert!(
        matches!(outcomes[0], AdminOutcome::Created { .. }),
        "{outcomes:?}"
    );
    assert_eq!(outcomes[1], AdminOutcome::Unchanged);
    assert_eq!(tenants::Entity::find().count(&conn).await.unwrap(), 1);
    assert_eq!(users::Entity::find().count(&conn).await.unwrap(), 1);
}
