//! Request context shared by the login API handlers.

use std::net::IpAddr;

use axum::http::{HeaderMap, header};
use entity::enums::Outcome;
use sea_orm::ConnectionTrait;
use uuid::Uuid;

use super::{AuthnResult, Outcome as StepOutcome, ip::ClientIp};
use crate::{
    app::AppState,
    audit,
    oidc::{error::ErrorCode, params::AuthRequest, redirect},
    tenancy::Tenant,
};

pub struct Ctx<'a> {
    pub state: &'a AppState,
    pub tenant: &'a Tenant,
    pub headers: &'a HeaderMap,
    pub ip: Option<IpAddr>,
    pub user_agent: Option<&'a str>,
}

impl<'a> Ctx<'a> {
    pub fn new(
        state: &'a AppState,
        tenant: &'a Tenant,
        ip: ClientIp,
        headers: &'a HeaderMap,
    ) -> Self {
        Self {
            state,
            tenant,
            headers,
            ip: ip.0,
            user_agent: headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok()),
        }
    }

    /// Records a sign-in attempt (`reason` is a fixed code, never input).
    /// Rate-limited attempts are not recorded: they cost an attacker
    /// nothing, so logging them would let anyone grow the table.
    pub async fn audit_sign_in(
        &self,
        conn: &impl ConnectionTrait,
        user_id: Option<Uuid>,
        outcome: Outcome,
        details: serde_json::Value,
    ) -> anyhow::Result<()> {
        audit::record(
            conn,
            audit::Event {
                tenant_id: self.tenant.id,
                actor: audit::Actor::User(user_id),
                event_type: audit::EventType::SignIn,
                target: user_id.map(audit::Target::User),
                outcome,
                ip: self.ip,
                details,
            },
        )
        .await
    }

    pub fn issuer(&self) -> String {
        self.state.config.issuer(&self.tenant.slug)
    }

    /// An RFC 6749 §4.1.2.1 error sent back to the (validated) redirect URI.
    pub fn error_redirect(
        &self,
        req: &AuthRequest,
        code: ErrorCode,
        description: &str,
    ) -> AuthnResult<StepOutcome> {
        let url = redirect::error_url(
            &req.redirect_uri,
            code,
            description,
            req.state.as_deref(),
            &self.issuer(),
        );
        Ok(StepOutcome::Redirect {
            url,
            cookies: Vec::new(),
        })
    }
}
