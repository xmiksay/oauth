//! `login_transactions` table: an `/authorize` request waiting for the user
//! to sign in and/or consent.

use sea_orm::entity::prelude::*;

use crate::enums::LoginStage;

// Debug is hand-written so the binding hash never reaches logs via `{:?}`.
#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "login_transactions")]
pub struct Model {
    /// Random (UUIDv4-shaped): it is the `tx` handle in the login URL.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// The client application.
    pub application_id: Uuid,
    /// Validated authorize parameters (`oidc::params::AuthRequest`).
    pub params: Json,
    pub stage: LoginStage,
    pub user_id: Option<Uuid>,
    pub amr: Vec<String>,
    pub auth_time: Option<DateTimeWithTimeZone>,
    /// Existing session being reused (consent-only transactions).
    pub session_id: Option<Uuid>,
    /// SHA-256 of the browser-binding cookie.
    pub binding_hash: Vec<u8>,
    /// Stage `link`: the upstream identity (IdP, subject, email, name) the
    /// local sign-in will link.
    pub pending_identity: Option<Json>,
    /// `{idp_id, generation}` of the IdP an upstream sign-in went through.
    pub federated: Option<Json>,
    pub created_at: DateTimeWithTimeZone,
    pub expires_at: DateTimeWithTimeZone,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("application_id", &self.application_id)
            .field("stage", &self.stage)
            .field("user_id", &self.user_id)
            .field("binding_hash", &"<redacted>")
            .field(
                "pending_identity",
                &self.pending_identity.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
