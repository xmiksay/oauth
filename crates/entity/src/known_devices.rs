//! `known_devices` table: browsers (device cookies) a user signed in from.

use sea_orm::entity::prelude::*;

// Debug is hand-written so the device cookie hash never reaches logs.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "known_devices")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// SHA-256 of the `__Host-oauth_dev` cookie value.
    pub device_hash: Vec<u8>,
    pub user_agent: Option<String>,
    pub first_seen: DateTimeWithTimeZone,
    pub last_seen: DateTimeWithTimeZone,
    pub expires_at: DateTimeWithTimeZone,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("user_id", &self.user_id)
            .field("device_hash", &"<redacted>")
            .field("user_agent", &self.user_agent)
            .field("first_seen", &self.first_seen)
            .field("last_seen", &self.last_seen)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
