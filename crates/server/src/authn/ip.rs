//! Client IP address for rate limiting and session records.
//!
//! Without `TRUSTED_PROXY_HEADER` the socket peer is used. With it (e.g.
//! `X-Forwarded-For`) the RIGHT-MOST entry of that header is used: it was
//! appended by our own ingress, which saw the real peer — every entry to its
//! left is client-controlled. This assumes exactly one trusted proxy hop
//! in front of the server; behind several, configure the outermost proxy to
//! overwrite (not append) a dedicated header such as `X-Real-IP`.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, request::Parts},
};

use crate::app::AppState;

pub fn client_ip(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted_header: Option<&str>,
) -> Option<IpAddr> {
    let from_header = trusted_header.and_then(|name| {
        // Several header lines are one comma-separated list (RFC 9110 §5.3).
        let last_line = headers.get_all(name).iter().next_back()?;
        let last = last_line.to_str().ok()?.rsplit(',').next()?.trim();
        parse_addr(last)
    });
    from_header.or_else(|| peer.map(|p| p.ip()))
}

/// Accepts `1.2.3.4`, `::1`, `1.2.3.4:567` and `[::1]:567`.
fn parse_addr(raw: &str) -> Option<IpAddr> {
    raw.parse::<IpAddr>()
        .ok()
        .or_else(|| raw.parse::<SocketAddr>().ok().map(|s| s.ip()))
}

/// Extractor wrapper; `None` when neither source is available (e.g. tests
/// driving the router without a socket).
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub Option<IpAddr>);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0);
        Ok(Self(client_ip(
            &parts.headers,
            peer,
            state.config.trusted_proxy_header.as_deref(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn peer() -> Option<SocketAddr> {
        Some("10.0.0.9:4321".parse().unwrap())
    }

    #[test]
    fn socket_peer_without_trusted_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6"));
        assert_eq!(
            client_ip(&headers, peer(), None),
            Some("10.0.0.9".parse().unwrap())
        );
        assert_eq!(client_ip(&headers, None, None), None);
    }

    #[test]
    fn rightmost_entry_of_trusted_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("6.6.6.6, 203.0.113.7"),
        );
        let xff = Some("x-forwarded-for");
        assert_eq!(
            client_ip(&headers, peer(), xff),
            Some("203.0.113.7".parse().unwrap())
        );
        // A spoofed first line does not matter; the last line wins.
        headers.append(
            "x-forwarded-for",
            HeaderValue::from_static("[2001:db8::1]:443"),
        );
        assert_eq!(
            client_ip(&headers, peer(), xff),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn falls_back_to_peer_when_header_missing_or_garbage() {
        let mut headers = HeaderMap::new();
        let xff = Some("x-forwarded-for");
        assert_eq!(
            client_ip(&headers, peer(), xff),
            Some("10.0.0.9".parse().unwrap())
        );
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, unknown"),
        );
        assert_eq!(
            client_ip(&headers, peer(), xff),
            Some("10.0.0.9".parse().unwrap())
        );
    }
}
