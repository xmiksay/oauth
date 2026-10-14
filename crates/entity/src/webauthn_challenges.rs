//! `webauthn_challenges` table: single-use WebAuthn ceremony challenges.

use sea_orm::entity::prelude::*;

use crate::enums::WebauthnPurpose;

// Debug is hand-written so the challenge hash never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "webauthn_challenges")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// SHA-256 of the base64url challenge string.
    pub challenge_hash: Vec<u8>,
    pub purpose: WebauthnPurpose,
    /// The user the ceremony is for (`None`: a login before the user is known).
    pub user_id: Option<Uuid>,
    /// The login transaction (`login` only).
    pub tx_id: Option<Uuid>,
    pub created_at: DateTimeWithTimeZone,
    pub expires_at: DateTimeWithTimeZone,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("challenge_hash", &"<redacted>")
            .field("purpose", &self.purpose)
            .field("user_id", &self.user_id)
            .field("tx_id", &self.tx_id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
