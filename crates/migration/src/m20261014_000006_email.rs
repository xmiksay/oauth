//! Email: the outgoing message outbox, single-use email link tokens
//! (verify / reset / invite / change), known sign-in devices and
//! per-event notification preferences.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261014_000006_email"
    }
}

// `outbox.kind` is a closed Rust enum but only shape-checked here (like
// audit event types): undelivered rows of a retired kind must stay valid.
// Outbox rows reference only the tenant: a queued notice about a user
// outlives nothing it needs, and the body is self-contained (sealed).
const UP: &str = r"
CREATE TABLE outbox (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    channel text NOT NULL CHECK (channel IN ('email', 'telegram')),
    recipient text NOT NULL CHECK (length(recipient) BETWEEN 1 AND 320),
    kind text NOT NULL CHECK (kind ~ '^[a-z_]+$'),
    subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 998),
    -- NULL once sent or dead: a delivered body (with its link token) isn't kept.
    body_enc bytea,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text CHECK (last_error ~ '^[a-z_]+$'),
    sent_at timestamptz,
    dead_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    -- A delivered or abandoned message keeps no (token-bearing) body.
    CHECK ((sent_at IS NULL AND dead_at IS NULL) OR body_enc IS NULL)
);
CREATE INDEX outbox_due ON outbox (channel, next_attempt_at)
    WHERE sent_at IS NULL AND dead_at IS NULL;
CREATE INDEX outbox_expires ON outbox (expires_at);

CREATE TABLE email_tokens (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    purpose text NOT NULL CHECK (purpose IN ('verify', 'reset', 'invite', 'change')),
    -- The user's address when the token was issued: redeeming requires it
    -- to still be the user's address.
    email text NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    new_email text CHECK (length(new_email) BETWEEN 3 AND 254),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((purpose = 'change') = (new_email IS NOT NULL)),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX email_tokens_user ON email_tokens (tenant_id, user_id, purpose);
CREATE INDEX email_tokens_expires ON email_tokens (expires_at);

CREATE TABLE known_devices (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    device_hash bytea NOT NULL CHECK (length(device_hash) = 32),
    user_agent text,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    UNIQUE (tenant_id, user_id, device_hash),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX known_devices_expires ON known_devices (expires_at);
-- Survives the sweep of expired devices: only a user who never signed in
-- gets no notice for their first device.
ALTER TABLE users ADD COLUMN first_device_at timestamptz;

-- No row = every channel on (notifications are opt-out).
CREATE TABLE notification_prefs (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    event text NOT NULL CHECK (event IN
        ('password_changed', 'mfa_changed', 'email_changed', 'new_sign_in', 'token_reuse')),
    email boolean NOT NULL DEFAULT true,
    telegram boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id, event),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
";

const DOWN: &str = r"
ALTER TABLE users DROP COLUMN first_device_at;
DROP TABLE notification_prefs;
DROP TABLE known_devices;
DROP TABLE email_tokens;
DROP TABLE outbox;
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
