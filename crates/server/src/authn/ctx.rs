//! Request context shared by the login API handlers.

use std::net::IpAddr;

use axum::http::{HeaderMap, header};

use super::{AuthnResult, Outcome, ip::ClientIp};
use crate::{
    app::AppState,
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

    pub fn issuer(&self) -> String {
        self.state.config.issuer(&self.tenant.slug)
    }

    /// An RFC 6749 §4.1.2.1 error sent back to the (validated) redirect URI.
    pub fn error_redirect(
        &self,
        req: &AuthRequest,
        code: ErrorCode,
        description: &str,
    ) -> AuthnResult<Outcome> {
        let url = redirect::error_url(
            &req.redirect_uri,
            code,
            description,
            req.state.as_deref(),
            &self.issuer(),
        );
        Ok(Outcome::Redirect {
            url,
            cookies: Vec::new(),
        })
    }
}
