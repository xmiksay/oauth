//! Groups in the ID token / userinfo (`id_token_groups`: none | all |
//! assigned) and `groups` as an OIDC scope.
//!
//! `groups` joins the OIDC scopes, which resource apps may not expose (stored
//! grants keep both kinds in one list, told apart by name). An existing
//! resource scope named `groups` (any case) is never renamed silently: the
//! migration aborts with the offending apps listed and leaves the fix to an
//! operator.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261122_000018_id_token_groups"
    }
}

// The lock keeps a still-running older replica from adding such a scope
// between the check and the end of this transaction.
const UP: &str = r"
LOCK TABLE app_scopes IN SHARE MODE;

DO $$
DECLARE
    taken text;
BEGIN
    SELECT string_agg(format('tenant %s: app %s scope %L (%s)', t.slug, a.client_id, s.value, s.id),
                      '; ' ORDER BY t.slug, a.client_id)
    INTO taken
    FROM app_scopes s
    JOIN applications a ON a.id = s.application_id
    JOIN tenants t ON t.id = a.tenant_id
    WHERE lower(s.value) = 'groups';
    IF taken IS NOT NULL THEN
        RAISE EXCEPTION '`groups` is now an OIDC scope and cannot be a resource scope value, but these exist: %. '
            'Rename them (UPDATE app_scopes SET value = ''<new>'' WHERE id = ''<id>''), then start again', taken;
    END IF;
END
$$;

ALTER TABLE applications ADD COLUMN id_token_groups text NOT NULL DEFAULT 'none'
    CONSTRAINT applications_id_token_groups_check CHECK (id_token_groups IN ('none', 'all', 'assigned'));
";

const DOWN: &str = r"
ALTER TABLE applications DROP COLUMN id_token_groups;
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
