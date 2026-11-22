//! Retired tenant slugs (#87): every slug the system tenant gave up through a
//! `SYSTEM_TENANT_RENAME`. Its old host and issuer are still known to relying
//! parties, bookmarks and upstream IdPs, so no regular tenant may take it.
//! Only `directory::system_tenant::reconcile_slug` writes it, in the rename's
//! transaction; `slug` is the key, so a slug retired twice keeps its first row.
//!
//! The schema enforces what the code relies on: a trigger refuses any UPDATE
//! or DELETE (append-only; the FK has no `ON DELETE CASCADE`, so the system
//! tenant can't be deleted out from under its history either) and any row
//! whose `tenant_id` is not the system tenant.
//!
//! Renames that ran before this table existed are backfilled from the
//! system tenant's `tenant.rename` audit events (`details.from`). One whose
//! audit row already fell to `audit_retention_days` can't be recovered.

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
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    retired_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX retired_tenant_slugs_tenant_idx ON retired_tenant_slugs (tenant_id);

CREATE FUNCTION retired_tenant_slugs_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'retired_tenant_slugs is append-only';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = NEW.tenant_id AND is_system) THEN
        RAISE EXCEPTION 'only the system tenant retires slugs';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER retired_tenant_slugs_guard
    BEFORE INSERT OR UPDATE OR DELETE ON retired_tenant_slugs
    FOR EACH ROW EXECUTE FUNCTION retired_tenant_slugs_guard();
CREATE TRIGGER retired_tenant_slugs_no_truncate
    BEFORE TRUNCATE ON retired_tenant_slugs
    FOR EACH STATEMENT EXECUTE FUNCTION retired_tenant_slugs_guard();

INSERT INTO retired_tenant_slugs (slug, tenant_id, retired_at)
SELECT e.details->>'from', e.tenant_id, min(e.at)
FROM audit_events e
JOIN tenants t ON t.id = e.tenant_id AND t.is_system
WHERE e.event_type = 'tenant.rename'
  AND e.outcome = 'success'
  AND e.details->>'from' ~ '^[a-z0-9][a-z0-9-]{1,62}$'
  AND e.details->>'from' <> t.slug
GROUP BY 1, 2
ON CONFLICT (slug) DO NOTHING;
";

const DOWN: &str = r"
DROP TABLE retired_tenant_slugs;
DROP FUNCTION retired_tenant_slugs_guard();
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
