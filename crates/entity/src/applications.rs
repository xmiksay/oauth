//! `applications` table.

use sea_orm::entity::prelude::*;

use crate::enums::{AccessTokenFormat, ClientType, SigningAlg};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "applications")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// Unique per tenant; the OAuth `client_id`.
    pub client_id: String,
    pub display_name: String,
    pub client_type: ClientType,
    pub builtin: bool,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    /// Audience / resource URI (e.g. `api://management-api`); unique per tenant.
    pub identifier_uri: Option<String>,
    pub access_token_format: AccessTokenFormat,
    pub signing_alg: SigningAlg,
    pub access_token_ttl_secs: i32,
    pub refresh_token_ttl_secs: i32,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
