//! `authorization_codes` table (code stored hashed, single use).

use sea_orm::entity::prelude::*;

// Debug is hand-written so secret material never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "authorization_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    #[sea_orm(unique)]
    pub code_hash: Vec<u8>,
    pub application_id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub redirect_uri: String,
    /// Granted scopes: OIDC scopes plus the resource's scope values.
    pub scopes: Vec<String>,
    pub resource_application_id: Option<Uuid>,
    pub nonce: Option<String>,
    /// PKCE S256 challenge.
    pub code_challenge: String,
    pub amr: Vec<String>,
    pub auth_time: DateTimeWithTimeZone,
    pub created_at: DateTimeWithTimeZone,
    pub expires_at: DateTimeWithTimeZone,
    pub consumed_at: Option<DateTimeWithTimeZone>,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("code_hash", &"<redacted>")
            .field("application_id", &self.application_id)
            .field("user_id", &self.user_id)
            .field("scopes", &self.scopes)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
