//! OIDC runtime state: browser sessions, login transactions, authorization
//! codes, refresh tokens, opaque access tokens and rate-limit buckets. Every
//! bearer value (cookie, code, token) is stored only as its SHA-256 hash.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261013_000004_oidc"
    }
}

// `session_id`, `authorization_code_id` and `family_id` are deliberately plain
// columns, not FKs: sessions and codes are swept on expiry while the tokens
// they produced live on, and the ids only serve as claims / revocation keys.
const UP: &str = r"
-- TOTP replay protection: the last accepted 30 s time step.
ALTER TABLE user_totp ADD COLUMN last_used_step bigint;

-- `api://X` is the client-id form of an audience, so an app may only claim it
-- for its own client_id; otherwise `api://X` could name two apps. The scheme
-- is matched case-insensitively so `API://X` can't slip past.
ALTER TABLE applications ADD CONSTRAINT applications_api_uri_is_own_client_id
    CHECK (identifier_uri IS NULL OR lower(identifier_uri) NOT LIKE 'api://%'
           OR identifier_uri = 'api://' || client_id);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    amr text[] NOT NULL,
    auth_time timestamptz NOT NULL,
    ip text,
    user_agent text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX sessions_user ON sessions (tenant_id, user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

CREATE TABLE login_transactions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    application_id uuid NOT NULL,
    params jsonb NOT NULL,
    stage text NOT NULL CHECK (stage IN ('password', 'mfa', 'change_password', 'consent')),
    user_id uuid,
    -- Set once the user authenticated in this transaction (else an existing
    -- session is being reused and `session_id` names it).
    amr text[] NOT NULL DEFAULT '{}',
    auth_time timestamptz,
    session_id uuid,
    -- SHA-256 of the browser-binding cookie set by /authorize: only the
    -- browser that started the transaction may drive it.
    binding_hash bytea NOT NULL CHECK (length(binding_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX login_transactions_expires ON login_transactions (expires_at);

CREATE TABLE authorization_codes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    code_hash bytea NOT NULL UNIQUE CHECK (length(code_hash) = 32),
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    scopes text[] NOT NULL,
    resource_application_id uuid,
    nonce text,
    code_challenge text NOT NULL,
    amr text[] NOT NULL,
    auth_time timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, resource_application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX authorization_codes_expires ON authorization_codes (expires_at);

CREATE TABLE refresh_tokens (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    family_id uuid NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    authorization_code_id uuid,
    scopes text[] NOT NULL,
    resource_application_id uuid,
    amr text[] NOT NULL,
    auth_time timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    rotated_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, resource_application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX refresh_tokens_family ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_code ON refresh_tokens (authorization_code_id)
    WHERE authorization_code_id IS NOT NULL;
CREATE INDEX refresh_tokens_expires ON refresh_tokens (expires_at);

CREATE TABLE opaque_access_tokens (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    application_id uuid NOT NULL,
    resource_application_id uuid,
    user_id uuid,
    authorization_code_id uuid,
    family_id uuid,
    claims jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, resource_application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX opaque_access_tokens_code ON opaque_access_tokens (authorization_code_id)
    WHERE authorization_code_id IS NOT NULL;
CREATE INDEX opaque_access_tokens_family ON opaque_access_tokens (family_id)
    WHERE family_id IS NOT NULL;
CREATE INDEX opaque_access_tokens_expires ON opaque_access_tokens (expires_at);

-- Fixed-window counters; `key_hash` = SHA-256 of the bucket key (which may
-- contain an email address, so it is not stored in clear).
CREATE TABLE rate_limit_buckets (
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    key_hash bytea NOT NULL CHECK (length(key_hash) = 32),
    window_start timestamptz NOT NULL,
    count integer NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, key_hash, window_start)
);
CREATE INDEX rate_limit_buckets_expires ON rate_limit_buckets (expires_at);
";

const DOWN: &str = r"
DROP TABLE rate_limit_buckets;
DROP TABLE opaque_access_tokens;
DROP TABLE refresh_tokens;
DROP TABLE authorization_codes;
DROP TABLE login_transactions;
DROP TABLE sessions;
ALTER TABLE applications DROP CONSTRAINT applications_api_uri_is_own_client_id;
ALTER TABLE user_totp DROP COLUMN last_used_step;
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
