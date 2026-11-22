//! `group_members` table.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "group_members")]
pub struct Model {
    pub tenant_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub group_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    pub created_at: DateTimeWithTimeZone,
    /// Added by an administrator (kept whatever the mappings say).
    pub manual: bool,
    /// Kept by this identity provider's group mappings; a sign-in through
    /// it removes the row (or just this mark, when `manual`) once the
    /// mapped claim value is gone.
    pub idp_id: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
