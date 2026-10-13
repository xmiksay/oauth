//! `signing_keys` table.

use sea_orm::entity::prelude::*;

use crate::enums::{KeyStatus, SigningAlg};

// Debug is hand-written so secret material never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "signing_keys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    #[sea_orm(unique)]
    pub kid: String,
    pub alg: SigningAlg,
    pub status: KeyStatus,
    /// AES-256-GCM `nonce || ciphertext`, AAD = tenant id || kid.
    pub private_key_enc: Vec<u8>,
    pub public_jwk: Json,
    pub created_at: DateTimeWithTimeZone,
    pub activated_at: Option<DateTimeWithTimeZone>,
    pub retired_at: Option<DateTimeWithTimeZone>,
    pub expires_at: Option<DateTimeWithTimeZone>,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .field("status", &self.status)
            .field("private_key_enc", &"<redacted>")
            .field("public_jwk", &self.public_jwk)
            .field("created_at", &self.created_at)
            .field("activated_at", &self.activated_at)
            .field("retired_at", &self.retired_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
