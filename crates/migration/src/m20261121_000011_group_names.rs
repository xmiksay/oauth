//! Group names become unique per tenant (case-insensitively) so they can be
//! emitted in the `groups` claim, and each app chooses what that claim
//! carries (`groups_claim_format`: group ids or names).
//!
//! Existing duplicates are never renamed silently: the migration aborts with
//! the offending groups listed and leaves the fix to an operator.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261121_000011_group_names"
    }
}

// The lock keeps a still-running older replica from creating a colliding
// name between the check and the index build (which would then fail with a
// bare unique violation instead of the list below). The index build takes
// this lock anyway.
const UP: &str = r"
LOCK TABLE groups IN SHARE MODE;

DO $$
DECLARE
    dups text;
BEGIN
    SELECT string_agg(format('tenant %s: %s', t.slug, d.names), '; ' ORDER BY t.slug, d.names)
    INTO dups
    FROM (
        SELECT tenant_id,
               string_agg(format('%L (%s)', display_name, id), ', ' ORDER BY id) AS names
        FROM groups
        GROUP BY tenant_id, lower(display_name)
        HAVING count(*) > 1
    ) d
    JOIN tenants t ON t.id = d.tenant_id;
    IF dups IS NOT NULL THEN
        RAISE EXCEPTION 'group names must be unique per tenant (case-insensitively) but these collide: %. '
            'Rename all but one of each (UPDATE groups SET display_name = ''<new>'' WHERE id = ''<id>''), '
            'then start again', dups;
    END IF;
END
$$;

CREATE UNIQUE INDEX groups_tenant_id_lower_display_name_key ON groups (tenant_id, lower(display_name));

ALTER TABLE applications ADD COLUMN groups_claim_format text NOT NULL DEFAULT 'id'
    CONSTRAINT applications_groups_claim_format_check CHECK (groups_claim_format IN ('id', 'name'));
";

const DOWN: &str = r"
ALTER TABLE applications DROP COLUMN groups_claim_format;
DROP INDEX groups_tenant_id_lower_display_name_key;
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
