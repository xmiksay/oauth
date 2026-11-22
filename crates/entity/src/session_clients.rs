//! `session_clients` table: the clients that obtained tokens in a browser
//! session — the recipients of its Back-Channel Logout.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "session_clients")]
pub struct Model {
    pub tenant_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub session_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub application_id: Uuid,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
