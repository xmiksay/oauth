//! `email_tokens` table: single-use links sent by email.

use sea_orm::entity::prelude::*;

use crate::enums::EmailTokenPurpose;

// Debug is hand-written so the token hash never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "email_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// SHA-256 of the link token.
    pub token_hash: Vec<u8>,
    pub purpose: EmailTokenPurpose,
    /// The user's address at issue time; the token only works while it
    /// still is.
    pub email: String,
    /// The address being verified (`change` only).
    pub new_email: Option<String>,
    pub expires_at: DateTimeWithTimeZone,
    pub consumed_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("user_id", &self.user_id)
            .field("token_hash", &"<redacted>")
            .field("purpose", &self.purpose)
            .field("email", &self.email)
            .field("new_email", &self.new_email)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
