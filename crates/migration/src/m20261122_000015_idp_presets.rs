//! Identity-provider presets: `kind` google / entra / github, Google's
//! hosted-domain restriction, Entra's allowed tenants for a multi-tenant
//! (`{tenantid}`-templated) issuer, and the per-IdP "trust the upstream
//! email" flag.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261122_000015_idp_presets"
    }
}

const UP: &str = r"
ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_kind_check;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_kind_check
    CHECK (kind IN ('oidc', 'google', 'entra', 'github'));
ALTER TABLE identity_providers
    ADD COLUMN hosted_domain text CHECK (length(hosted_domain) BETWEEN 1 AND 253),
    ADD COLUMN allowed_tenants text[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(allowed_tenants) <= 50),
    ADD COLUMN trust_upstream_email boolean NOT NULL DEFAULT false;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_hosted_domain_google
    CHECK (hosted_domain IS NULL OR kind = 'google');
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_allowed_tenants_entra
    CHECK (cardinality(allowed_tenants) = 0 OR kind = 'entra');
";

const DOWN: &str = r"
ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_allowed_tenants_entra;
ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_hosted_domain_google;
ALTER TABLE identity_providers
    DROP COLUMN trust_upstream_email,
    DROP COLUMN allowed_tenants,
    DROP COLUMN hosted_domain;
DELETE FROM identity_providers WHERE kind <> 'oidc';
ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_kind_check;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_kind_check
    CHECK (kind IN ('oidc'));
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
