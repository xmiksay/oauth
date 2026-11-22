//! Federation group mappings: per identity provider, an upstream claim
//! value (`claim` = `value`) puts the signed-in user into a local group.
//! `group_members` records where a membership comes from: `manual` (added
//! by an administrator) and/or `idp_id` (kept by that provider's mappings).
//! A sign-in only ever adds or removes rows its own provider owns.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261122_000014_idp_group_mappings"
    }
}

const UP: &str = r"
CREATE TABLE idp_group_mappings (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    idp_id uuid NOT NULL,
    claim text NOT NULL CHECK (claim ~ '^[A-Za-z0-9_.:/-]{1,64}$'),
    value text NOT NULL CHECK (octet_length(value) BETWEEN 1 AND 256),
    group_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, idp_id, claim, value, group_id),
    FOREIGN KEY (tenant_id, idp_id) REFERENCES identity_providers (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idp_group_mappings_group ON idp_group_mappings (tenant_id, group_id);

ALTER TABLE group_members ADD COLUMN manual boolean NOT NULL DEFAULT true;
ALTER TABLE group_members ADD COLUMN idp_id uuid;
ALTER TABLE group_members ADD CONSTRAINT group_members_source_check
    CHECK (manual OR idp_id IS NOT NULL);
ALTER TABLE group_members ADD CONSTRAINT group_members_idp_fk
    FOREIGN KEY (tenant_id, idp_id) REFERENCES identity_providers (tenant_id, id)
    ON DELETE SET NULL (idp_id);
CREATE INDEX group_members_idp ON group_members (tenant_id, idp_id, user_id)
    WHERE idp_id IS NOT NULL;
";

const DOWN: &str = r"
DELETE FROM group_members WHERE NOT manual;
DROP INDEX group_members_idp;
ALTER TABLE group_members DROP CONSTRAINT group_members_idp_fk;
ALTER TABLE group_members DROP CONSTRAINT group_members_source_check;
ALTER TABLE group_members DROP COLUMN idp_id;
ALTER TABLE group_members DROP COLUMN manual;
DROP TABLE idp_group_mappings;
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
