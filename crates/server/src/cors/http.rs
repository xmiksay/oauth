//! CORS response headers and preflight answers. `Access-Control-Allow-Origin`
//! echoes the request's `Origin` only when it is allowed; credentials are
//! never allowed (the endpoints take bearer tokens / client ids, not
//! cookies); every response says `Vary: Origin`.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::{allows, tenant_allows};
use crate::{
    app::AppState,
    oidc::{client_auth, params},
    tenancy::Tenant,
};

const ALLOW_HEADERS: &str = "authorization, content-type";
const MAX_AGE_SECS: &str = "600";

/// The request's cross-origin `Origin`: `None` when absent, repeated,
/// unreadable or the tenant's own origin (same-origin needs no CORS).
fn cross_origin<'a>(state: &AppState, tenant: &Tenant, headers: &'a HeaderMap) -> Option<&'a str> {
    let mut values = headers.get_all(header::ORIGIN).iter();
    let origin = values.next()?.to_str().ok()?;
    if values.next().is_some() || origin == state.config.tenant_origin(&tenant.slug) {
        return None;
    }
    Some(origin)
}

/// `Vary: Origin` always; `Access-Control-Allow-Origin` for `allowed`.
fn decorate(mut response: Response, allowed: Option<&str>) -> Response {
    let headers = response.headers_mut();
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
    if let Some(value) = allowed.and_then(|o| HeaderValue::from_str(o).ok()) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    response
}

/// Fails closed: a lookup error is logged and grants nothing.
fn granted(result: anyhow::Result<bool>) -> bool {
    result
        .map_err(|err| tracing::error!(error = ?err, "CORS origin lookup failed"))
        .unwrap_or(false)
}

async fn tenant_origin_allowed<'a>(
    state: &AppState,
    tenant: &Tenant,
    headers: &'a HeaderMap,
) -> Option<&'a str> {
    let origin = cross_origin(state, tenant, headers)?;
    granted(tenant_allows(&state.db, tenant.id, origin).await).then_some(origin)
}

/// Middleware for the tenant-wide endpoints (discovery, JWKS, userinfo):
/// any origin some app of the tenant allows. Preflights are answered by
/// their own handlers and pass through untouched.
pub async fn tenant_wide(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }
    let Some(tenant) = req.extensions().get::<Tenant>().cloned() else {
        return next.run(req).await;
    };
    let headers = req.headers().clone();
    let response = next.run(req).await;
    let allowed = tenant_origin_allowed(&state, &tenant, &headers).await;
    decorate(response, allowed)
}

/// Token / revoke responses: only an origin the client named in the
/// request allows (Basic user name, else the form's `client_id`) — whether
/// or not its authentication then succeeded, so an SPA can read errors.
pub async fn for_client(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    body: &[u8],
    response: Response,
) -> Response {
    let Some(origin) = cross_origin(state, tenant, headers) else {
        return decorate(response, None);
    };
    let form = params::parse_unique(body).unwrap_or_default();
    let Some(client_id) = client_auth::claimed_client_id(headers, &form) else {
        return decorate(response, None);
    };
    let client = client_auth::find_client(&state.db, tenant.id, &client_id).await;
    let ok = granted(client.map(|app| app.is_some_and(|app| allows(&app, origin))));
    decorate(response, ok.then_some(origin))
}

/// Answers a preflight. A preflight carries no credentials or body, so it
/// can't name the client: any origin some app of the tenant allows passes,
/// and the actual response is then gated per client ([`for_client`]).
async fn preflight(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    methods: &'static str,
) -> Response {
    let response = StatusCode::NO_CONTENT.into_response();
    let requested = headers
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|m| m.to_str().ok());
    if !requested.is_some_and(|m| methods.split(", ").any(|allowed| allowed == m)) {
        return decorate(response, None);
    }
    let Some(origin) = tenant_origin_allowed(state, tenant, headers).await else {
        return decorate(response, None);
    };
    let mut response = decorate(response, Some(origin));
    let out = response.headers_mut();
    out.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(methods),
    );
    out.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(ALLOW_HEADERS),
    );
    out.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static(MAX_AGE_SECS),
    );
    response
}

/// `OPTIONS` of discovery / JWKS.
pub async fn preflight_get(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
) -> Response {
    preflight(&state, &tenant, &headers, "GET").await
}

/// `OPTIONS` of userinfo.
pub async fn preflight_get_post(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
) -> Response {
    preflight(&state, &tenant, &headers, "GET, POST").await
}

/// `OPTIONS` of token / revoke.
pub async fn preflight_post(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
) -> Response {
    preflight(&state, &tenant, &headers, "POST").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decorate_varies_and_echoes_only_allowed() {
        let plain = decorate(StatusCode::OK.into_response(), None);
        assert_eq!(plain.headers()[header::VARY], "Origin");
        assert!(
            !plain
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
        let allowed = decorate(StatusCode::OK.into_response(), Some("https://a.example"));
        assert_eq!(
            allowed.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://a.example"
        );
        assert!(
            !allowed
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
        );
    }

    #[test]
    fn lookup_errors_grant_nothing() {
        assert!(!granted(Err(anyhow::anyhow!("db down"))));
        assert!(granted(Ok(true)));
    }
}
