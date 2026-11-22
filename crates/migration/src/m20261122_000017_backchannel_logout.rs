//! Logout hygiene and OpenID Connect Back-Channel Logout 1.0.
//!
//! - `tenants.logout_revokes_refresh_tokens`: RP-initiated logout also
//!   revokes the refresh-token families started in the ended session.
//! - `applications.backchannel_logout_uri` / `_session_required`: where a
//!   client wants its signed logout tokens.
//! - `session_clients`: which clients obtained tokens in which session (the
//!   recipients of a back-channel logout). Rows go with their session (also
//!   on expiry sweeps) and with their application.
//! - `outbox.channel` gains `backchannel` (logout token deliveries).

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261122_000017_backchannel_logout"
    }
}

const UP: &str = r"
ALTER TABLE tenants ADD COLUMN logout_revokes_refresh_tokens boolean NOT NULL DEFAULT true;
ALTER TABLE applications ADD COLUMN backchannel_logout_uri text
    CONSTRAINT applications_backchannel_logout_uri_check
    CHECK (length(backchannel_logout_uri) BETWEEN 1 AND 2048);
ALTER TABLE applications ADD COLUMN backchannel_logout_session_required boolean
    NOT NULL DEFAULT false;
ALTER TABLE sessions ADD CONSTRAINT sessions_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE TABLE session_clients (
    tenant_id uuid NOT NULL,
    session_id uuid NOT NULL,
    application_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, application_id),
    FOREIGN KEY (tenant_id, session_id) REFERENCES sessions (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE
);
CREATE INDEX session_clients_application ON session_clients (tenant_id, application_id);
ALTER TABLE outbox DROP CONSTRAINT outbox_channel_check;
ALTER TABLE outbox ADD CONSTRAINT outbox_channel_check
    CHECK (channel IN ('email', 'telegram', 'backchannel'));
";

const DOWN: &str = r"
DELETE FROM outbox WHERE channel = 'backchannel';
ALTER TABLE outbox DROP CONSTRAINT outbox_channel_check;
ALTER TABLE outbox ADD CONSTRAINT outbox_channel_check
    CHECK (channel IN ('email', 'telegram'));
DROP TABLE session_clients;
ALTER TABLE sessions DROP CONSTRAINT sessions_tenant_id_id_key;
ALTER TABLE applications DROP COLUMN backchannel_logout_session_required;
ALTER TABLE applications DROP COLUMN backchannel_logout_uri;
ALTER TABLE tenants DROP COLUMN logout_revokes_refresh_tokens;
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
