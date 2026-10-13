//! `refresh_tokens` table: opaque, rotating, grouped into families.

use sea_orm::entity::prelude::*;

// Debug is hand-written so secret material never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "refresh_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    #[sea_orm(unique)]
    pub token_hash: Vec<u8>,
    /// Every rotation of one grant shares the family; reuse revokes it all.
    pub family_id: Uuid,
    pub application_id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub authorization_code_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub resource_application_id: Option<Uuid>,
    pub amr: Vec<String>,
    pub auth_time: DateTimeWithTimeZone,
    pub created_at: DateTimeWithTimeZone,
    pub expires_at: DateTimeWithTimeZone,
    pub rotated_at: Option<DateTimeWithTimeZone>,
    pub revoked_at: Option<DateTimeWithTimeZone>,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("token_hash", &"<redacted>")
            .field("family_id", &self.family_id)
            .field("application_id", &self.application_id)
            .field("user_id", &self.user_id)
            .field("scopes", &self.scopes)
            .field("expires_at", &self.expires_at)
            .field("rotated_at", &self.rotated_at)
            .field("revoked_at", &self.revoked_at)
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
