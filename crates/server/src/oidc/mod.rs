//! OAuth 2.1 / OpenID Connect protocol endpoints on each tenant host.
//! Issuer = the tenant origin `{scheme}://{tenant}.{PUBLIC_URL host}[:port]`.

mod authorize;
pub mod client_auth;
mod discovery;
pub mod error;
mod introspect;
mod logout;
pub mod params;
pub mod pkce;
pub mod redirect;
mod refresh_grant;
mod revoke;
pub mod scope;
mod token;
mod userinfo;

use axum::{
    Router,
    handler::Handler,
    http::{HeaderMap, header},
    middleware,
    routing::{get, post},
};

use crate::app::AppState;

pub fn router(state: AppState) -> Router<AppState> {
    let csrf = middleware::from_fn_with_state(state, crate::authn::csrf);
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(discovery::configuration),
        )
        .route("/discovery/keys", get(discovery::jwks))
        .route("/oauth2/authorize", get(authorize::authorize))
        .route("/oauth2/token", post(token::token))
        .route(
            "/oauth2/userinfo",
            get(userinfo::userinfo).post(userinfo::userinfo),
        )
        .route("/oauth2/introspect", post(introspect::introspect))
        .route("/oauth2/revoke", post(revoke::revoke))
        .route(
            "/oauth2/logout",
            get(logout::logout).post(logout::sign_out.layer(csrf)),
        )
}

/// Parses a form body after checking its content type.
fn form_params(
    headers: &HeaderMap,
    body: &[u8],
) -> error::OAuthResult<std::collections::HashMap<String, String>> {
    // Back-channel endpoints take form bodies.
    if !crate::headers::content_type_is(headers, "application/x-www-form-urlencoded") {
        return Err(error::OAuthError::invalid_request(
            "Content-Type must be application/x-www-form-urlencoded",
        ));
    }
    params::parse_unique(body).map_err(error::OAuthError::invalid_request)
}

/// The token of an `Authorization: Bearer …` header (RFC 6750 §2.1).
pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn bearer_extraction() {
        let mut h = HeaderMap::new();
        assert_eq!(bearer(&h), None);
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(bearer(&h), Some("abc"));
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer  xyz "),
        );
        assert_eq!(bearer(&h), Some("xyz"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer(&h), None);
    }

    #[test]
    fn form_content_type_required() {
        let mut h = HeaderMap::new();
        assert!(form_params(&h, b"a=1").is_err());
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        assert_eq!(form_params(&h, b"a=1").unwrap()["a"], "1");
    }
}
