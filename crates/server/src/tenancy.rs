//! Tenant resolution from the request host: tenant `t` lives only at
//! `t.{PUBLIC_URL host}[:port]`; the apex itself only redirects to the
//! system tenant's admin portal and receives the Telegram webhook (which
//! belongs to no tenant). `X-Forwarded-Host` / `Forwarded` are
//! ignored on purpose: the issuer is derived from the host, and a client
//! that could pick it would mint itself another tenant's origin.

use std::sync::Arc;

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{HeaderMap, Method, Uri, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use entity::tenants;

use crate::{
    app::AppState,
    config::HostKind,
    directory::{
        self,
        slug::{self, SYSTEM_TENANT_SLUG},
    },
    error::AppError,
    oidc::redirect,
    telegram::webhook,
};

/// The active tenant whose host the request was sent to. Unknown and
/// disabled tenants are indistinguishable (404). Resolved once per request by
/// [`resolve_host`] and kept in the request extensions.
#[derive(Clone, Debug)]
pub struct Tenant(pub Arc<tenants::Model>);

impl std::ops::Deref for Tenant {
    type Target = tenants::Model;

    fn deref(&self) -> &tenants::Model {
        &self.0
    }
}

impl FromRequestParts<AppState> for Tenant {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _: &AppState) -> Result<Self, AppError> {
        // Set by `resolve_host`; a route outside it has no tenant.
        parts
            .extensions
            .get::<Tenant>()
            .cloned()
            .ok_or(AppError::NotFound)
    }
}

/// Classifies the request authority. An absolute-form target or an HTTP/2
/// `:authority` wins over `Host` (RFC 9112 §3.2.2).
fn host_kind(state: &AppState, uri: &Uri, headers: &HeaderMap) -> HostKind {
    uri.authority()
        .map(|a| a.as_str())
        .or_else(|| headers.get(header::HOST)?.to_str().ok())
        .map_or(HostKind::Foreign, |a| state.config.public_url.host_kind(a))
}

async fn active(state: &AppState, slug: &str) -> Result<Option<Tenant>, AppError> {
    // Startup refuses enabled tenants with a now-invalid slug; this also
    // covers one re-enabled at runtime (`www` must never serve a sign-in page).
    Ok(directory::find_tenant_by_slug(&state.db, slug)
        .await?
        .filter(|t| !t.disabled && (t.is_system || slug::validate(&t.slug).is_ok()))
        .map(|t| Tenant(Arc::new(t))))
}

/// Gate in front of every host-scoped route: tenant hosts get their
/// [`Tenant`] resolved, the apex answers `GET /` with a redirect to the
/// system admin portal and passes the Telegram webhook on (without a
/// tenant), everything else is 404.
pub async fn resolve_host(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    // Proxies and servers may disagree on which of several `Host`s counts
    // (RFC 9112 §3.2: such a request is invalid), so none is believed.
    if req.headers().get_all(header::HOST).iter().nth(1).is_some() {
        return AppError::BadRequest("more than one Host header".into()).into_response();
    }
    let webhook = req.uri().path() == webhook::PATH;
    match host_kind(&state, req.uri(), req.headers()) {
        HostKind::Tenant(_) if webhook => AppError::NotFound.into_response(),
        HostKind::Tenant(slug) => match active(&state, &slug).await {
            Ok(Some(tenant)) => {
                req.extensions_mut().insert(tenant);
                next.run(req).await
            }
            Ok(None) => AppError::NotFound.into_response(),
            Err(err) => err.into_response(),
        },
        HostKind::Apex if webhook => next.run(req).await,
        HostKind::Apex
            if req.uri().path() == "/" && matches!(*req.method(), Method::GET | Method::HEAD) =>
        {
            let admin = format!("{}/admin", state.config.tenant_origin(SYSTEM_TENANT_SLUG));
            redirect::found(&admin)
        }
        _ => AppError::NotFound.into_response(),
    }
}
