//! `user_recovery_codes` table.

use sea_orm::entity::prelude::*;

// Debug is hand-written so secret material never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "user_recovery_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// SHA-256 of the code.
    pub code_hash: Vec<u8>,
    pub used_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("user_id", &self.user_id)
            .field("code_hash", &"<redacted>")
            .field("used_at", &self.used_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
