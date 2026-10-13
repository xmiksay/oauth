//! Closed value sets. Stored as `text` with a matching `CHECK` constraint (see
//! the migration crate docs for why not Postgres enum types).

use sea_orm::entity::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum UserType {
    #[sea_orm(string_value = "member")]
    Member,
    #[sea_orm(string_value = "guest")]
    Guest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum DirectoryRole {
    #[sea_orm(string_value = "GlobalAdmin")]
    GlobalAdmin,
    #[sea_orm(string_value = "ApplicationAdmin")]
    ApplicationAdmin,
    #[sea_orm(string_value = "UserAdmin")]
    UserAdmin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum ClientType {
    #[sea_orm(string_value = "confidential")]
    Confidential,
    #[sea_orm(string_value = "public")]
    Public,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum AccessTokenFormat {
    #[sea_orm(string_value = "jwt")]
    Jwt,
    #[sea_orm(string_value = "opaque")]
    Opaque,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum SigningAlg {
    #[sea_orm(string_value = "RS256")]
    Rs256,
    #[sea_orm(string_value = "ES256")]
    Es256,
}

impl SigningAlg {
    /// JOSE `alg` name (RFC 7518).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Text")]
pub enum KeyStatus {
    /// Published in JWKS, not yet signing.
    #[sea_orm(string_value = "next")]
    Next,
    #[sea_orm(string_value = "active")]
    Active,
    /// No longer signing; published until `expires_at`.
    #[sea_orm(string_value = "retired")]
    Retired,
}

/// Values of `app_roles.allowed_member_types` (a `text[]`; the DB CHECK also
/// allows `user`).
pub mod member_type {
    pub const APPLICATION: &str = "application";
}
