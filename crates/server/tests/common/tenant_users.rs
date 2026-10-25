//! Setup for the system admin's `/api/v1/tenants/{slug}/users` suites.

use entity::{audit_events, tenants, users};
use oauth_server::{bootstrap, directory};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use uuid::Uuid;

use super::{flow::Fixture, mgmt::mint_user_token};

pub fn sys(path: &str) -> String {
    super::at("system", path)
}

pub fn users_of(slug: &str, rest: &str) -> String {
    sys(&format!("/api/v1/tenants/{slug}/users{rest}"))
}

/// The fixture plus a bootstrapped system tenant, its root Global Admin and
/// a management token of theirs.
pub async fn setup() -> (Fixture, tenants::Model, users::Model, String) {
    setup_on(Fixture::new().await).await
}

pub async fn setup_on(f: Fixture) -> (Fixture, tenants::Model, users::Model, String) {
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
    (f, system, root, token)
}

/// `event_type` audit rows about `user` in `tenant_id`, oldest first.
pub async fn events(
    f: &Fixture,
    tenant_id: Uuid,
    event_type: &str,
    user: Uuid,
) -> Vec<audit_events::Model> {
    audit_events::Entity::find()
        .filter(audit_events::Column::TenantId.eq(tenant_id))
        .filter(audit_events::Column::EventType.eq(event_type))
        .filter(audit_events::Column::TargetId.eq(user))
        .order_by_asc(audit_events::Column::Id)
        .all(&f.db)
        .await
        .unwrap()
}
