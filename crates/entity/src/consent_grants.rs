//! `consent_grants` table.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "consent_grants")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_application_id: Uuid,
    pub resource_application_id: Uuid,
    /// `None` = admin consent on behalf of every user in the tenant.
    pub user_id: Option<Uuid>,
    /// Granted scope values of the resource app.
    pub scopes: Vec<String>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
