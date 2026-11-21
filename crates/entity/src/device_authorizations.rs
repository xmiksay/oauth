//! `device_authorizations` table: device authorization grant requests
//! (RFC 8628), both codes stored hashed.

use sea_orm::entity::prelude::*;

use crate::enums::DeviceStatus;

// Debug is hand-written so secret material never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "device_authorizations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// The client application (the device).
    pub application_id: Uuid,
    #[sea_orm(unique)]
    pub device_code_hash: Vec<u8>,
    /// SHA-256 of the normalised user code; unique per tenant.
    pub user_code_hash: Vec<u8>,
    /// Requested scopes: OIDC scopes plus the resource's scope values.
    pub scopes: Vec<String>,
    pub resource_application_id: Option<Uuid>,
    pub status: DeviceStatus,
    /// Who approved or denied it.
    pub user_id: Option<Uuid>,
    /// Of the approving sign-in.
    pub amr: Vec<String>,
    pub auth_time: Option<DateTimeWithTimeZone>,
    /// Minimum seconds between polls; grows with every `slow_down`.
    pub interval_secs: i32,
    pub last_polled_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
    pub expires_at: DateTimeWithTimeZone,
    pub decided_at: Option<DateTimeWithTimeZone>,
    pub consumed_at: Option<DateTimeWithTimeZone>,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("application_id", &self.application_id)
            .field("device_code_hash", &"<redacted>")
            .field("user_code_hash", &"<redacted>")
            .field("scopes", &self.scopes)
            .field("status", &self.status)
            .field("user_id", &self.user_id)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
