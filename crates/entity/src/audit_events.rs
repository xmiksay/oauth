//! `audit_events` table: append-only record of sign-ins and mutations.

use sea_orm::entity::prelude::*;

use crate::enums::{ActorType, Outcome};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_events")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub at: DateTimeWithTimeZone,
    pub actor_type: ActorType,
    /// `None` for `system`, or a sign-in attempt for an unknown account.
    pub actor_id: Option<Uuid>,
    /// One of `oauth_server::audit::EventType` (dotted, e.g. `user.create`).
    pub event_type: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub outcome: Outcome,
    pub ip: Option<String>,
    /// Never secrets, passwords or tokens.
    pub details: Json,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
