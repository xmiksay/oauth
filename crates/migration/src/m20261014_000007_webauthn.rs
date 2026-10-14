//! Passkeys (WebAuthn): registered credentials, single-use ceremony
//! challenges and the per-user WebAuthn user handle.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261014_000007_webauthn"
    }
}

// `users.webauthn_handle` is generated lazily at the first registration (an
// UPDATE … WHERE webauthn_handle IS NULL), so no backfill and no pgcrypto
// extension are needed inside the migration transaction.
// `public_key` is the COSE_Key exactly as the authenticator sent it; `alg`
// repeats its algorithm so the DB can refuse anything the verifier can't use.
const UP: &str = r"
ALTER TABLE users ADD COLUMN webauthn_handle bytea
    CHECK (length(webauthn_handle) = 32);
CREATE UNIQUE INDEX users_tenant_webauthn_handle ON users (tenant_id, webauthn_handle);

ALTER TABLE login_transactions ADD CONSTRAINT login_transactions_tenant_id_id
    UNIQUE (tenant_id, id);

CREATE TABLE webauthn_credentials (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    credential_id bytea NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 1023),
    public_key bytea NOT NULL CHECK (length(public_key) BETWEEN 1 AND 2048),
    alg integer NOT NULL CHECK (alg IN (-7, -8, -257)),
    sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
    rp_id text NOT NULL CHECK (length(rp_id) BETWEEN 1 AND 253),
    transports text[] NOT NULL DEFAULT '{}' CHECK (cardinality(transports) <= 8),
    aaguid uuid NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    backup_eligible boolean NOT NULL,
    backup_state boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    -- A synced passkey is backup-eligible by definition (WebAuthn §6.1).
    CHECK (backup_eligible OR NOT backup_state),
    UNIQUE (tenant_id, credential_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials (tenant_id, user_id);

CREATE TABLE webauthn_challenges (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    challenge_hash bytea NOT NULL UNIQUE CHECK (length(challenge_hash) = 32),
    purpose text NOT NULL CHECK (purpose IN ('register', 'login', 'reauth')),
    user_id uuid,
    tx_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    -- Login challenges belong to a login transaction (user known only at the
    -- MFA step); the others always to a user and never to a transaction.
    CHECK (CASE purpose
        WHEN 'login' THEN tx_id IS NOT NULL
        ELSE user_id IS NOT NULL AND tx_id IS NULL
    END),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, tx_id) REFERENCES login_transactions (tenant_id, id)
        ON DELETE CASCADE
);
CREATE INDEX webauthn_challenges_user ON webauthn_challenges (tenant_id, user_id, purpose);
CREATE INDEX webauthn_challenges_tx ON webauthn_challenges (tx_id);
CREATE INDEX webauthn_challenges_expires ON webauthn_challenges (expires_at);
";

const DOWN: &str = r"
DROP TABLE webauthn_challenges;
DROP TABLE webauthn_credentials;
ALTER TABLE login_transactions DROP CONSTRAINT login_transactions_tenant_id_id;
DROP INDEX users_tenant_webauthn_handle;
ALTER TABLE users DROP COLUMN webauthn_handle;
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
