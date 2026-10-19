//! `federation_states` table: single-use state of one upstream round trip
//! (OAuth `state`, OIDC `nonce`, PKCE verifier), 10 minutes.

use sea_orm::entity::prelude::*;

use crate::enums::FederationPurpose;

// Debug is hand-written so neither the state hash, the nonce nor the sealed
// verifier reach logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "federation_states")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// The login transaction (`purpose = login`).
    pub tx_id: Option<Uuid>,
    pub idp_id: Uuid,
    /// SHA-256 of the `state` sent upstream.
    pub state_hash: Vec<u8>,
    /// SHA-256 of the browser's tx-binding cookie.
    pub binding_hash: Vec<u8>,
    pub nonce: String,
    /// AES-256-GCM, AAD `keys::wrap::pkce_aad`.
    pub pkce_verifier_sealed: Vec<u8>,
    /// The IdP's `generation` when the round trip began.
    pub idp_generation: i64,
    pub purpose: FederationPurpose,
    /// The user linking from My Account (`purpose = link`).
    pub user_id: Option<Uuid>,
    /// The delegated session that started a My Account link.
    pub session_id: Option<Uuid>,
    pub created_at: DateTimeWithTimeZone,
    pub expires_at: DateTimeWithTimeZone,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("tx_id", &self.tx_id)
            .field("idp_id", &self.idp_id)
            .field("state_hash", &"<redacted>")
            .field("binding_hash", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("pkce_verifier_sealed", &"<redacted>")
            .field("purpose", &self.purpose)
            .field("user_id", &self.user_id)
            .field("session_id", &self.session_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
