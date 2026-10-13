//! `rate_limit_buckets` table: fixed-window attempt counters.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "rate_limit_buckets")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub tenant_id: Uuid,
    /// SHA-256 of the bucket key (keys may contain an email address).
    #[sea_orm(primary_key, auto_increment = false)]
    pub key_hash: Vec<u8>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub window_start: DateTimeWithTimeZone,
    pub count: i32,
    pub expires_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
