//! Retired tenant slugs (#87): every slug the system tenant gave up through a
//! `SYSTEM_TENANT_RENAME`. Its old host and issuer are still known to relying
//! parties, bookmarks and upstream IdPs, so no regular tenant may take it.
//! Append-only (`directory::system_tenant::reconcile_slug` writes it in the
//! rename's transaction); `slug` is the key, so a slug retired twice keeps
//! its first row.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261122_000021_retired_tenant_slugs"
    }
}

const UP: &str = r"
CREATE TABLE retired_tenant_slugs (
    slug text PRIMARY KEY CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    retired_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX retired_tenant_slugs_tenant_idx ON retired_tenant_slugs (tenant_id);
";

const DOWN: &str = r"
DROP TABLE retired_tenant_slugs;
";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(UP).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(DOWN).await?;
        Ok(())
    }
}
