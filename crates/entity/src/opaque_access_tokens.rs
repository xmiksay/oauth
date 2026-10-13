//! `opaque_access_tokens` table: reference tokens resolved by introspection.

use sea_orm::entity::prelude::*;

// Debug is hand-written so secret material never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "opaque_access_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    #[sea_orm(unique)]
    pub token_hash: Vec<u8>,
    /// The client the token was issued to.
    pub application_id: Uuid,
    pub resource_application_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub authorization_code_id: Option<Uuid>,
    pub family_id: Option<Uuid>,
    /// The same claims a JWT access token would carry.
    pub claims: Json,
    pub created_at: DateTimeWithTimeZone,
    pub expires_at: DateTimeWithTimeZone,
    pub revoked_at: Option<DateTimeWithTimeZone>,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("token_hash", &"<redacted>")
            .field("application_id", &self.application_id)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
