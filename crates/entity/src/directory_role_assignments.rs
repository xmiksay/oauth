//! `directory_role_assignments` table.

use sea_orm::entity::prelude::*;

use crate::enums::DirectoryRole;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "directory_role_assignments")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub role: DirectoryRole,
    /// Created or adopted by `oauth apply`, which may delete it.
    pub managed: bool,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
