//! App registrations: secrets, exposed scopes / roles, required permissions,
//! role assignments and consent grants.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261013_000002_applications"
    }
}

// References to a scope/role go through `(resource_application_id, id)` so a
// row can't point at a scope of a different app than the resource it names.
// Those FKs are MATCH SIMPLE: skipped when the nullable member is NULL, which
// is how the "exactly one of" columns below stay optional.
const UP: &str = r"
CREATE TABLE applications (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 128),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    client_type text NOT NULL CHECK (client_type IN ('confidential', 'public')),
    builtin boolean NOT NULL DEFAULT false,
    redirect_uris text[] NOT NULL DEFAULT '{}',
    post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
    identifier_uri text,
    access_token_format text NOT NULL DEFAULT 'jwt'
        CHECK (access_token_format IN ('jwt', 'opaque')),
    signing_alg text NOT NULL DEFAULT 'RS256' CHECK (signing_alg IN ('RS256', 'ES256')),
    -- Upper bound keeps key retirement (max access-token TTL + 1h) bounded.
    access_token_ttl_secs integer NOT NULL DEFAULT 3600
        CHECK (access_token_ttl_secs BETWEEN 300 AND 86400),
    refresh_token_ttl_secs integer NOT NULL DEFAULT 1209600
        CHECK (refresh_token_ttl_secs > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, client_id),
    UNIQUE (tenant_id, identifier_uri)
);

CREATE TABLE client_secrets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    application_id uuid NOT NULL,
    secret_hash bytea NOT NULL CHECK (length(secret_hash) = 32),
    hint text NOT NULL,
    description text,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE
);
CREATE INDEX client_secrets_app ON client_secrets (tenant_id, application_id);

-- RFC 6749 scope-token: printable ASCII except space, double quote, backslash.
CREATE TABLE app_scopes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    application_id uuid NOT NULL,
    value text NOT NULL CHECK (value ~ '^[!#-\[\]-~]{1,120}$'),
    description text NOT NULL DEFAULT '',
    admin_consent_required boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, value),
    UNIQUE (application_id, id),
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE
);

CREATE TABLE app_roles (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    application_id uuid NOT NULL,
    value text NOT NULL CHECK (value ~ '^[!#-\[\]-~]{1,120}$'),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    description text NOT NULL DEFAULT '',
    allowed_member_types text[] NOT NULL CHECK (
        cardinality(allowed_member_types) > 0
        AND allowed_member_types <@ ARRAY['user', 'application']::text[]
    ),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, value),
    UNIQUE (application_id, id),
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE
);

-- What a client app asks for: a delegated scope XOR an application role.
CREATE TABLE app_required_permissions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    application_id uuid NOT NULL,
    resource_application_id uuid NOT NULL,
    scope_id uuid,
    app_role_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(scope_id, app_role_id) = 1),
    UNIQUE NULLS NOT DISTINCT (application_id, scope_id, app_role_id),
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, resource_application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (resource_application_id, scope_id) REFERENCES app_scopes (application_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (resource_application_id, app_role_id) REFERENCES app_roles (application_id, id)
        ON DELETE CASCADE
);
CREATE INDEX app_required_permissions_resource
    ON app_required_permissions (tenant_id, resource_application_id);
CREATE INDEX app_required_permissions_scope ON app_required_permissions (scope_id);
CREATE INDEX app_required_permissions_role ON app_required_permissions (app_role_id);

-- Principal is exactly one of user / group / client application; separate FK
-- columns (instead of type + id) so deleting a principal cascades.
CREATE TABLE app_role_assignments (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    resource_application_id uuid NOT NULL,
    app_role_id uuid NOT NULL,
    user_id uuid,
    group_id uuid,
    client_application_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(user_id, group_id, client_application_id) = 1),
    UNIQUE NULLS NOT DISTINCT (app_role_id, user_id, group_id, client_application_id),
    FOREIGN KEY (tenant_id, resource_application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (resource_application_id, app_role_id) REFERENCES app_roles (application_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, client_application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE
);
CREATE INDEX app_role_assignments_resource
    ON app_role_assignments (tenant_id, resource_application_id);
CREATE INDEX app_role_assignments_user ON app_role_assignments (tenant_id, user_id)
    WHERE user_id IS NOT NULL;
CREATE INDEX app_role_assignments_group ON app_role_assignments (tenant_id, group_id)
    WHERE group_id IS NOT NULL;
CREATE INDEX app_role_assignments_client ON app_role_assignments (tenant_id, client_application_id)
    WHERE client_application_id IS NOT NULL;

-- user_id NULL = admin consent on behalf of every user of the tenant.
CREATE TABLE consent_grants (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    client_application_id uuid NOT NULL,
    resource_application_id uuid NOT NULL,
    user_id uuid,
    scopes text[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (client_application_id, resource_application_id, user_id),
    FOREIGN KEY (tenant_id, client_application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, resource_application_id) REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX consent_grants_resource ON consent_grants (tenant_id, resource_application_id);
CREATE INDEX consent_grants_user ON consent_grants (tenant_id, user_id)
    WHERE user_id IS NOT NULL;
";

const DOWN: &str = r"
DROP TABLE consent_grants;
DROP TABLE app_role_assignments;
DROP TABLE app_required_permissions;
DROP TABLE app_roles;
DROP TABLE app_scopes;
DROP TABLE client_secrets;
DROP TABLE applications;
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
