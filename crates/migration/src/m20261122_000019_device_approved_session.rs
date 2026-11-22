//! The browser session that approved a device request
//! (`device_authorizations.approved_session_id`).
//!
//! Redemption refuses an approval whose session has ended, like the code
//! flow refuses a code whose session ended: signing out of (or revoking) the
//! approving session clears the column through the FK, and redemption denies
//! a row without it. Rows approved before this migration have none and are
//! refused too (they live 15 minutes at most).

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261122_000019_device_approved_session"
    }
}

// `SET NULL (col)` (Postgres 15+) clears only the session column: `tenant_id`
// is part of the composite FK and must stay.
const UP: &str = r"
ALTER TABLE device_authorizations ADD COLUMN approved_session_id uuid;
ALTER TABLE device_authorizations
    ADD CONSTRAINT device_authorizations_approved_session_fkey
    FOREIGN KEY (tenant_id, approved_session_id) REFERENCES sessions (tenant_id, id)
    ON DELETE SET NULL (approved_session_id);
ALTER TABLE device_authorizations
    ADD CONSTRAINT device_authorizations_approved_session_only_approved
    CHECK (approved_session_id IS NULL OR status = 'approved');
-- FK action on session deletion.
CREATE INDEX device_authorizations_approved_session
    ON device_authorizations (tenant_id, approved_session_id)
    WHERE approved_session_id IS NOT NULL;
";

const DOWN: &str = r"
ALTER TABLE device_authorizations DROP COLUMN approved_session_id;
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
