//! `identity_providers` table: a tenant's upstream OpenID providers.

use sea_orm::entity::prelude::*;

use crate::enums::{IdpClientAuth, IdpKind, IdpPolicy};

// Debug is hand-written so the sealed client secret never reaches logs.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "identity_providers")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub kind: IdpKind,
    pub enabled: bool,
    /// Offered as a "Sign in with …" button (hidden ones are reachable via
    /// home-realm discovery only).
    pub visible: bool,
    pub issuer: String,
    /// `None`: `{issuer}/.well-known/openid-configuration`.
    pub discovery_url: Option<String>,
    pub client_id: String,
    /// AES-256-GCM under `OAUTH_MASTER_KEY`, AAD `keys::wrap::idp_aad`.
    pub client_secret_sealed: Option<Vec<u8>>,
    pub client_auth: IdpClientAuth,
    pub scopes: Vec<String>,
    pub policy: IdpPolicy,
    pub trust_upstream_mfa: bool,
    pub mfa_acr: Option<String>,
    /// Lower-case DNS names for home-realm discovery.
    pub email_domains: Vec<String>,
    /// Bumped on every repoint (issuer, client id, discovery URL).
    pub generation: i64,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("enabled", &self.enabled)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret_sealed", &"<redacted>")
            .field("policy", &self.policy)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
