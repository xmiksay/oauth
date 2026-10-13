//! Tenants, users (+ TOTP, recovery codes), groups and directory roles.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261013_000001_directory"
    }
}

// Child tables reference parents through `(tenant_id, id)` composite keys, so
// the database itself refuses a row that links objects of two tenants.
const UP: &str = r"
CREATE TABLE tenants (
    id uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    is_system boolean NOT NULL DEFAULT false,
    disabled boolean NOT NULL DEFAULT false,
    audit_retention_days integer NOT NULL DEFAULT 90 CHECK (audit_retention_days > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
-- At most one system tenant.
CREATE UNIQUE INDEX tenants_single_system ON tenants (is_system) WHERE is_system;

CREATE TABLE users (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_type text NOT NULL DEFAULT 'member' CHECK (user_type IN ('member', 'guest')),
    email text NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    email_verified boolean NOT NULL DEFAULT false,
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    password_hash text,
    must_change_password boolean NOT NULL DEFAULT false,
    disabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX users_tenant_email ON users (tenant_id, lower(email));

CREATE TABLE user_totp (
    user_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    secret_enc bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    confirmed_at timestamptz,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE user_recovery_codes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    code_hash bytea NOT NULL CHECK (length(code_hash) = 32),
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX user_recovery_codes_user ON user_recovery_codes (tenant_id, user_id);

CREATE TABLE groups (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    description text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE TABLE group_members (
    tenant_id uuid NOT NULL,
    group_id uuid NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX group_members_user ON group_members (tenant_id, user_id);

CREATE TABLE directory_role_assignments (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL CHECK (role IN ('GlobalAdmin', 'ApplicationAdmin', 'UserAdmin')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id, role),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
";

const DOWN: &str = r"
DROP TABLE directory_role_assignments;
DROP TABLE group_members;
DROP TABLE groups;
DROP TABLE user_recovery_codes;
DROP TABLE user_totp;
DROP TABLE users;
DROP TABLE tenants;
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
