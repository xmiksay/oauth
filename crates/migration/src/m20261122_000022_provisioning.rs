//! Declarative provisioning (`oauth apply`): `managed` marks the rows apply
//! created or adopted. Apply deletes only managed rows that its file no
//! longer declares, so objects created through the API / UI are never
//! touched. A separate marker table can't reference these tables with
//! composite FKs, so the marker lives on each row. Apply also audits as its
//! own actor type.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261122_000022_provisioning"
    }
}

const TABLES: [&str; 11] = [
    "applications",
    "app_scopes",
    "app_roles",
    "app_required_permissions",
    "groups",
    "group_members",
    "users",
    "directory_role_assignments",
    "app_role_assignments",
    "consent_grants",
    "identity_providers",
];

const UP_AUDIT: &str = r"
ALTER TABLE audit_events DROP CONSTRAINT audit_events_actor_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_actor_type_check
    CHECK (actor_type IN ('user', 'application', 'system', 'apply'));
";

const DOWN_AUDIT: &str = r"
DELETE FROM audit_events WHERE actor_type = 'apply';
ALTER TABLE audit_events DROP CONSTRAINT audit_events_actor_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_actor_type_check
    CHECK (actor_type IN ('user', 'application', 'system'));
";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        for table in TABLES {
            conn.execute_unprepared(&format!(
                "ALTER TABLE {table} ADD COLUMN managed boolean NOT NULL DEFAULT false"
            ))
            .await?;
        }
        conn.execute_unprepared(UP_AUDIT).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(DOWN_AUDIT).await?;
        for table in TABLES {
            conn.execute_unprepared(&format!("ALTER TABLE {table} DROP COLUMN managed"))
                .await?;
        }
        Ok(())
    }
}
