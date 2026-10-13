//! `user_totp` table.

use sea_orm::entity::prelude::*;

// Debug is hand-written so secret material never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "user_totp")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    /// AES-256-GCM wrapped with `OAUTH_MASTER_KEY`.
    pub secret_enc: Vec<u8>,
    pub created_at: DateTimeWithTimeZone,
    pub confirmed_at: Option<DateTimeWithTimeZone>,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("user_id", &self.user_id)
            .field("tenant_id", &self.tenant_id)
            .field("secret_enc", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("confirmed_at", &self.confirmed_at)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
