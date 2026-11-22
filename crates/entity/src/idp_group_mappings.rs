//! `idp_group_mappings` table: an upstream claim value of an identity
//! provider that puts the signed-in user into a local group.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "idp_group_mappings")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub idp_id: Uuid,
    /// Top-level ID token claim name, e.g. `groups` or `roles`.
    pub claim: String,
    /// Matched exactly against the claim's string value(s).
    pub value: String,
    pub group_id: Uuid,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
