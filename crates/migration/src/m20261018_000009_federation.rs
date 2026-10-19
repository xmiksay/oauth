//! Upstream OIDC federation: per-tenant identity providers, the upstream
//! identities linked to users, the single-use state of upstream round trips,
//! and the `link` login stage with its pending identity.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261018_000009_federation"
    }
}

// `email_domains` uniqueness across a tenant's IdPs is enforced by the API
// (an array column can't carry a cross-row UNIQUE).
// One identity per (IdP, subject), and a user links at most one identity per
// IdP. A federation state belongs either to a login transaction (`login`) or
// to a signed-in user linking from My Account (`link`); `binding_hash` ties it
// to the browser that started it either way.
const UP: &str = r"
CREATE TABLE identity_providers (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    kind text NOT NULL DEFAULT 'oidc' CHECK (kind IN ('oidc')),
    enabled boolean NOT NULL DEFAULT true,
    visible boolean NOT NULL DEFAULT true,
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    discovery_url text CHECK (length(discovery_url) BETWEEN 1 AND 2048),
    client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 512),
    client_secret_sealed bytea,
    client_auth text NOT NULL DEFAULT 'post' CHECK (client_auth IN ('post', 'basic')),
    scopes text[] NOT NULL DEFAULT '{openid,email,profile}',
    policy text NOT NULL DEFAULT 'link_only' CHECK (policy IN ('jit', 'link_only', 'deny')),
    trust_upstream_mfa boolean NOT NULL DEFAULT false,
    mfa_acr text CHECK (length(mfa_acr) BETWEEN 1 AND 256),
    email_domains text[] NOT NULL DEFAULT '{}',
    -- Bumped whenever issuer, client or discovery URL change: work verified
    -- against an older configuration must not land (see federation.md).
    generation bigint NOT NULL DEFAULT 1 CHECK (generation >= 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE user_identities (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    idp_id uuid NOT NULL,
    subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    email text CHECK (length(email) BETWEEN 1 AND 320),
    linked_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    UNIQUE (tenant_id, idp_id, subject),
    UNIQUE (tenant_id, user_id, idp_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, idp_id) REFERENCES identity_providers (tenant_id, id)
        ON DELETE CASCADE
);

CREATE TABLE federation_states (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    tx_id uuid,
    idp_id uuid NOT NULL,
    state_hash bytea NOT NULL UNIQUE CHECK (length(state_hash) = 32),
    binding_hash bytea NOT NULL CHECK (length(binding_hash) = 32),
    nonce text NOT NULL CHECK (length(nonce) BETWEEN 1 AND 128),
    pkce_verifier_sealed bytea NOT NULL,
    idp_generation bigint NOT NULL,
    purpose text NOT NULL CHECK (purpose IN ('login', 'link')),
    user_id uuid,
    -- The delegated session a My Account link was started from; the
    -- callback requires it to still be live.
    session_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    CHECK ((purpose = 'login') = (tx_id IS NOT NULL)),
    CHECK ((purpose = 'link') = (session_id IS NOT NULL)),
    CHECK ((purpose = 'link') = (user_id IS NOT NULL)),
    FOREIGN KEY (tenant_id, tx_id) REFERENCES login_transactions (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, idp_id) REFERENCES identity_providers (tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX federation_states_expires ON federation_states (expires_at);
-- Lookups replacing earlier states, and the FK cascades from transactions,
-- users and providers. (user_identities' unique keys already lead with
-- (tenant_id, idp_id) and (tenant_id, user_id).)
CREATE INDEX federation_states_tx ON federation_states (tenant_id, tx_id);
CREATE INDEX federation_states_user ON federation_states (tenant_id, user_id);
CREATE INDEX federation_states_idp ON federation_states (tenant_id, idp_id);

ALTER TABLE login_transactions DROP CONSTRAINT login_transactions_stage_check;
ALTER TABLE login_transactions ADD CONSTRAINT login_transactions_stage_check
    CHECK (stage IN ('password', 'mfa', 'change_password', 'consent', 'link'));
ALTER TABLE login_transactions ADD COLUMN pending_identity jsonb;
-- {idp_id, generation} of an upstream sign-in waiting at mfa / change_password
-- / consent: completion requires that configuration still in force.
ALTER TABLE login_transactions ADD COLUMN federated jsonb;

ALTER TABLE notification_prefs DROP CONSTRAINT notification_prefs_event_check;
ALTER TABLE notification_prefs ADD CONSTRAINT notification_prefs_event_check
    CHECK (event IN ('password_changed', 'mfa_changed', 'email_changed', 'new_sign_in',
                     'token_reuse', 'identity_linked'));
";

const DOWN: &str = r"
DELETE FROM notification_prefs WHERE event = 'identity_linked';
ALTER TABLE notification_prefs DROP CONSTRAINT notification_prefs_event_check;
ALTER TABLE notification_prefs ADD CONSTRAINT notification_prefs_event_check
    CHECK (event IN ('password_changed', 'mfa_changed', 'email_changed', 'new_sign_in',
                     'token_reuse'));
DELETE FROM login_transactions WHERE stage = 'link';
ALTER TABLE login_transactions DROP COLUMN pending_identity;
ALTER TABLE login_transactions DROP COLUMN federated;
ALTER TABLE login_transactions DROP CONSTRAINT login_transactions_stage_check;
ALTER TABLE login_transactions ADD CONSTRAINT login_transactions_stage_check
    CHECK (stage IN ('password', 'mfa', 'change_password', 'consent'));
DROP TABLE federation_states;
DROP TABLE user_identities;
DROP TABLE identity_providers;
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
