//! `applications` table.

use sea_orm::entity::prelude::*;

use crate::enums::{
    AccessTokenFormat, AppMfaPolicy, ClientType, GroupsClaimFormat, IdTokenGroups, SigningAlg,
};

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
    /// Explicitly allowed CORS origins (`scheme://host[:port]`).
    pub web_origins: Vec<String>,
    /// Audience / resource URI (e.g. `api://management-api`); unique per tenant.
    pub identifier_uri: Option<String>,
    pub access_token_format: AccessTokenFormat,
    pub signing_alg: SigningAlg,
    /// What the `groups` claim carries: in access tokens for this (resource)
    /// app, and in its own ID tokens / userinfo responses (as client).
    pub groups_claim_format: GroupsClaimFormat,
    /// Which groups this (client) app's ID tokens and userinfo list.
    pub id_token_groups: IdTokenGroups,
    /// Only principals holding one of this app's roles (user: directly or
    /// via a group; app: an application permission) get tokens to / for it.
    pub assignment_required: bool,
    pub access_token_ttl_secs: i32,
    pub refresh_token_ttl_secs: i32,
    /// Opt-in to the device authorization grant (RFC 8628).
    pub device_code_enabled: bool,
    /// `required` forces MFA for sign-ins to this app (as client or resource).
    pub mfa_policy: AppMfaPolicy,
    /// OIDC Back-Channel Logout 1.0: where logout tokens are POSTed.
    pub backchannel_logout_uri: Option<String>,
    /// The client wants `sid` in logout tokens (we always send it).
    pub backchannel_logout_session_required: bool,
    /// Created or adopted by `oauth apply`, which may delete it.
    pub managed: bool,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
