//! Per-application "assignment required" (Entra's "User assignment
//! required"): when set, only principals holding one of the app's roles get
//! tokens to or for it. Existing apps keep today's behaviour (`false`).

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261122_000016_assignment_required"
    }
}

const UP: &str = r"
ALTER TABLE applications ADD COLUMN assignment_required boolean NOT NULL DEFAULT false;
";

const DOWN: &str = r"
ALTER TABLE applications DROP COLUMN assignment_required;
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
