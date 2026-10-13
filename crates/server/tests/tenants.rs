// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use entity::{applications, signing_keys, tenants};
use oauth_server::directory::{self, DirectoryError, NewTenant};
use sea_orm::{ConnectionTrait, EntityTrait, PaginatorTrait};

const NEW: NewTenant<'static> = NewTenant {
    slug: "contoso",
    display_name: "Contoso",
};

#[tokio::test]
async fn failure_late_in_provisioning_rolls_everything_back() {
    let (_pg, conn, config) = common::migrated_db().await;

    // Make the very last provisioning step (admin consent) fail.
    conn.execute_unprepared(
        "CREATE FUNCTION test_fail() RETURNS trigger LANGUAGE plpgsql AS \
           $$ BEGIN RAISE EXCEPTION 'injected failure'; END $$; \
         CREATE TRIGGER test_fail BEFORE INSERT ON consent_grants \
           FOR EACH ROW EXECUTE FUNCTION test_fail();",
    )
    .await
    .unwrap();
    let err = directory::create_tenant(&conn, &config, NEW)
        .await
        .unwrap_err();
    assert!(matches!(err, DirectoryError::Internal(_)), "{err:?}");

    assert_eq!(tenants::Entity::find().count(&conn).await.unwrap(), 0);
    assert_eq!(signing_keys::Entity::find().count(&conn).await.unwrap(), 0);
    assert_eq!(applications::Entity::find().count(&conn).await.unwrap(), 0);

    // Once the fault is gone the same slug is free again.
    conn.execute_unprepared("DROP TRIGGER test_fail ON consent_grants; DROP FUNCTION test_fail();")
        .await
        .unwrap();
    directory::create_tenant(&conn, &config, NEW).await.unwrap();
}

#[tokio::test]
async fn tenants_are_found_by_slug() {
    let (_pg, conn, config) = common::migrated_db().await;
    let created = directory::create_tenant(&conn, &config, NEW).await.unwrap();

    let found = directory::find_tenant_by_slug(&conn, "contoso")
        .await
        .unwrap()
        .expect("tenant by slug");
    assert_eq!(found.id, created.id);
    assert_eq!(found.display_name, "Contoso");
    assert!(
        directory::find_tenant_by_slug(&conn, "fabrikam")
            .await
            .unwrap()
            .is_none()
    );
    // Not the system tenant, and none exists yet.
    assert!(
        directory::find_system_tenant(&conn)
            .await
            .unwrap()
            .is_none()
    );
}
