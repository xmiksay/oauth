//! Small HTTP header helpers shared by the protocol and login endpoints.

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use tower_http::set_header::SetResponseHeaderLayer;

/// True if the request's media type (parameters ignored) is `mime`.
pub fn content_type_is(headers: &HeaderMap, mime: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case(mime))
}

/// App-wide response headers: nothing we serve (login SPA, consent screen,
/// protocol endpoints) may be framed (clickjacking), and URLs carrying codes
/// or transaction ids must not leak through `Referer`. Applied only when a
/// handler didn't set the header itself.
pub fn security_layers() -> [SetResponseHeaderLayer<HeaderValue>; 3] {
    let layer = |name: HeaderName, value: &'static str| {
        SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value))
    };
    [
        layer(header::X_FRAME_OPTIONS, "DENY"),
        layer(header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'"),
        layer(header::REFERRER_POLICY, "no-referrer"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_detection() {
        let mut h = HeaderMap::new();
        assert!(!content_type_is(&h, "application/json"));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/JSON; charset=utf-8"),
        );
        assert!(content_type_is(&h, "application/json"));
        assert!(!content_type_is(&h, "application/x-www-form-urlencoded"));
    }
}
