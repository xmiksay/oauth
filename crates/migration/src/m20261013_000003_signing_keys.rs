//! Per-tenant token signing keys (private half AES-256-GCM wrapped).

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261013_000003_signing_keys"
    }
}

// Partial unique indexes are checked per statement (they can't be DEFERRABLE),
// so rotation must retire the old active key before promoting the next one.
const UP: &str = r"
CREATE TABLE signing_keys (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kid text NOT NULL UNIQUE,
    alg text NOT NULL CHECK (alg IN ('RS256', 'ES256')),
    status text NOT NULL CHECK (status IN ('next', 'active', 'retired')),
    private_key_enc bytea NOT NULL,
    public_jwk jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    retired_at timestamptz,
    -- A retired key stays in JWKS until this instant.
    expires_at timestamptz,
    CHECK (status <> 'active' OR activated_at IS NOT NULL),
    CHECK (status <> 'retired' OR (retired_at IS NOT NULL AND expires_at IS NOT NULL))
);
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys (tenant_id, alg)
    WHERE status = 'active';
CREATE UNIQUE INDEX signing_keys_one_next ON signing_keys (tenant_id, alg)
    WHERE status = 'next';
CREATE INDEX signing_keys_tenant_status ON signing_keys (tenant_id, status);
";

const DOWN: &str = "DROP TABLE signing_keys;";

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
