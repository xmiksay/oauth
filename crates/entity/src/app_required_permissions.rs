//! `app_required_permissions` table.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "app_required_permissions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// The client app that requests the permission.
    pub application_id: Uuid,
    pub resource_application_id: Uuid,
    /// Delegated permission; exactly one of `scope_id` / `app_role_id` is set.
    pub scope_id: Option<Uuid>,
    /// Application permission.
    pub app_role_id: Option<Uuid>,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
