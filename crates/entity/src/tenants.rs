//! `tenants` table.

use sea_orm::entity::prelude::*;

use crate::enums::MfaPolicy;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "tenants")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub slug: String,
    pub display_name: String,
    pub is_system: bool,
    pub disabled: bool,
    pub audit_retention_days: i32,
    pub mfa_policy: MfaPolicy,
    /// RP-initiated logout also revokes the session's refresh-token families.
    pub logout_revokes_refresh_tokens: bool,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
