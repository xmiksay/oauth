//! `users` table.

use sea_orm::entity::prelude::*;

use crate::enums::UserType;

// Debug is hand-written so secret material never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_type: UserType,
    /// Unique per tenant case-insensitively (index on `lower(email)`).
    pub email: String,
    pub email_verified: bool,
    pub display_name: String,
    /// argon2id PHC string; `None` = no local password.
    pub password_hash: Option<String>,
    pub must_change_password: bool,
    pub disabled: bool,
    /// When the user's first sign-in device was recorded; `None` = never
    /// signed in (no "new sign-in" notice for the very first one).
    pub first_device_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("user_type", &self.user_type)
            .field("email", &self.email)
            .field("email_verified", &self.email_verified)
            .field("display_name", &self.display_name)
            .field("password_hash", &"<redacted>")
            .field("must_change_password", &self.must_change_password)
            .field("disabled", &self.disabled)
            .field("first_device_at", &self.first_device_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
