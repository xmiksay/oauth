//! `client_secrets` table.

use sea_orm::entity::prelude::*;

// Debug is hand-written so secret material never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "client_secrets")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub application_id: Uuid,
    /// SHA-256 of the secret.
    pub secret_hash: Vec<u8>,
    /// First characters of the secret, for display.
    pub hint: String,
    pub description: Option<String>,
    pub expires_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("application_id", &self.application_id)
            .field("secret_hash", &"<redacted>")
            .field("hint", &self.hint)
            .field("description", &self.description)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
