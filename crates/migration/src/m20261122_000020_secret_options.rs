//! Client secret options (#46):
//! - `tenants.allow_non_expiring_secrets`: the tenant lets app admins create
//!   client secrets without an expiry (`client_secrets.expires_at IS NULL`,
//!   already allowed by the schema).
//! - `client_secrets.expiry_notified_at`: when the expiry warning for the
//!   secret was queued (`jobs::secret_expiry`), so it goes out once.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261122_000020_secret_options"
    }
}

const UP: &str = r"
ALTER TABLE tenants ADD COLUMN allow_non_expiring_secrets boolean NOT NULL DEFAULT false;
ALTER TABLE client_secrets ADD COLUMN expiry_notified_at timestamptz;
CREATE INDEX client_secrets_expiry_pending_idx ON client_secrets (expires_at)
    WHERE expires_at IS NOT NULL AND expiry_notified_at IS NULL;
";

const DOWN: &str = r"
DROP INDEX client_secrets_expiry_pending_idx;
ALTER TABLE client_secrets DROP COLUMN expiry_notified_at;
ALTER TABLE tenants DROP COLUMN allow_non_expiring_secrets;
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
