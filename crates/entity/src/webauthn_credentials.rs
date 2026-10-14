//! `webauthn_credentials` table: registered passkeys. Nothing here is
//! secret (public keys and credential ids), so `Debug` is derived.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "webauthn_credentials")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// Unique per tenant.
    pub credential_id: Vec<u8>,
    /// COSE_Key as registered.
    pub public_key: Vec<u8>,
    /// COSE algorithm: -7 ES256, -8 EdDSA, -257 RS256.
    pub alg: i32,
    pub sign_count: i64,
    /// RP ID the credential was created for (the tenant host).
    pub rp_id: String,
    pub transports: Vec<String>,
    pub aaguid: Uuid,
    pub name: String,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub created_at: DateTimeWithTimeZone,
    pub last_used_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
