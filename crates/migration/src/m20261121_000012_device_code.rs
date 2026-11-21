//! Device authorization grant (RFC 8628): the per-app opt-in flag and the
//! pending device authorizations.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261121_000012_device_code"
    }
}

// Both codes are stored as SHA-256 only. The user code is short (typed by a
// human), so it must be unique among a tenant's rows; the device code is a
// 256-bit bearer value. A row is `pending` until a signed-in user approves or
// denies it (`user_id` = who decided), and an approved row is redeemed at most
// once (`consumed_at`). `interval_secs` grows with every `slow_down`.
const UP: &str = r"
ALTER TABLE applications ADD COLUMN device_code_enabled boolean NOT NULL DEFAULT false;

CREATE TABLE device_authorizations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    application_id uuid NOT NULL,
    device_code_hash bytea NOT NULL UNIQUE CHECK (length(device_code_hash) = 32),
    user_code_hash bytea NOT NULL CHECK (length(user_code_hash) = 32),
    scopes text[] NOT NULL,
    resource_application_id uuid,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied')),
    user_id uuid,
    amr text[] NOT NULL DEFAULT '{}',
    auth_time timestamptz,
    interval_secs integer NOT NULL CHECK (interval_secs BETWEEN 1 AND 60),
    last_polled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    decided_at timestamptz,
    consumed_at timestamptz,
    UNIQUE (tenant_id, user_code_hash),
    CHECK ((status = 'pending') = (user_id IS NULL)),
    CHECK ((status = 'pending') = (decided_at IS NULL)),
    CHECK (status <> 'approved' OR auth_time IS NOT NULL),
    CHECK (consumed_at IS NULL OR status = 'approved'),
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, resource_application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX device_authorizations_expires ON device_authorizations (expires_at);
-- FK cascades from applications and users.
CREATE INDEX device_authorizations_app ON device_authorizations (tenant_id, application_id);
CREATE INDEX device_authorizations_resource
    ON device_authorizations (tenant_id, resource_application_id)
    WHERE resource_application_id IS NOT NULL;
CREATE INDEX device_authorizations_user ON device_authorizations (tenant_id, user_id)
    WHERE user_id IS NOT NULL;
";

const DOWN: &str = r"
DROP TABLE device_authorizations;
ALTER TABLE applications DROP COLUMN device_code_enabled;
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
