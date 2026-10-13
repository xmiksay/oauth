//! `app_role_assignments` table.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "app_role_assignments")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub resource_application_id: Uuid,
    pub app_role_id: Uuid,
    /// The principal: exactly one of user / group / client application.
    pub user_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub client_application_id: Option<Uuid>,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
