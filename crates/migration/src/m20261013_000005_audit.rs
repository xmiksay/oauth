//! Append-only audit log of sign-ins and directory mutations, plus the
//! indexes and bounds the management API relies on.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261013_000005_audit"
    }
}

// `event_type` / `target_type` are closed enums in Rust
// (`oauth_server::audit`) but only shape-checked here: rows of an event type
// retired later must stay valid history, and the log is append-only, so an
// `IN (…)` list could only ever grow. Actor ids are plain columns (no FK):
// events outlive the users and apps they mention.
const UP: &str = r"
CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    at timestamptz NOT NULL DEFAULT now(),
    actor_type text NOT NULL CHECK (actor_type IN ('user', 'application', 'system')),
    actor_id uuid,
    event_type text NOT NULL CHECK (event_type ~ '^[a-z_]+(\.[a-z_]+)*$'),
    target_type text CHECK (target_type ~ '^[a-z_]+$'),
    target_id uuid,
    outcome text NOT NULL CHECK (outcome IN ('success', 'failure')),
    ip text,
    details jsonb NOT NULL DEFAULT '{}'
);
-- Newest-first listing per tenant (cursor = id, UUIDv7 ~ insertion order)
-- and the retention sweep by age.
CREATE INDEX audit_events_tenant_id ON audit_events (tenant_id, id DESC);
CREATE INDEX audit_events_tenant_at ON audit_events (tenant_id, at);
CREATE INDEX audit_events_target ON audit_events (tenant_id, target_id, id DESC)
    WHERE target_id IS NOT NULL;
CREATE INDEX audit_events_actor ON audit_events (tenant_id, actor_id, id DESC)
    WHERE actor_id IS NOT NULL;

-- Management API revocations: per signed-out session, per withdrawn
-- (client, resource) consent.
CREATE INDEX refresh_tokens_session ON refresh_tokens (tenant_id, session_id);
CREATE INDEX refresh_tokens_grant
    ON refresh_tokens (tenant_id, application_id, resource_application_id);
CREATE INDEX opaque_access_tokens_grant
    ON opaque_access_tokens (tenant_id, application_id, resource_application_id);

-- Refresh-token families live at most 90 days (the API caps public
-- clients lower).
ALTER TABLE applications ADD CONSTRAINT applications_refresh_ttl_max
    CHECK (refresh_token_ttl_secs <= 7776000);
";

const DOWN: &str = r"
ALTER TABLE applications DROP CONSTRAINT applications_refresh_ttl_max;
DROP INDEX opaque_access_tokens_grant;
DROP INDEX refresh_tokens_grant;
DROP INDEX refresh_tokens_session;
DROP TABLE audit_events;
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
