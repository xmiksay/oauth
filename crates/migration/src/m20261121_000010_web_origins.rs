//! Per-application allowed web origins for CORS on the protocol endpoints.
//! Only the explicit list is stored: the origins of a public client's
//! redirect URIs are added at request time, so nothing is backfilled.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261121_000010_web_origins"
    }
}

// The origin format itself is validated by the API (`cors::validate_origin`).
const UP: &str = r"
ALTER TABLE applications ADD COLUMN web_origins text[] NOT NULL DEFAULT '{}'
    CONSTRAINT applications_web_origins_count CHECK (cardinality(web_origins) <= 32);
";

const DOWN: &str = r"
ALTER TABLE applications DROP COLUMN web_origins;
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
