//! Redirect URI matching and building redirects with protocol parameters.

use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use super::error::ErrorCode;

/// Loopback hosts whose port is ignored (RFC 8252 §7.3). `localhost` is
/// deliberately excluded (RFC 8252 §8.3: it may resolve off-host).
const LOOPBACK_PREFIXES: [&str; 2] = ["http://127.0.0.1", "http://[::1]"];

/// Exact string match against the registered URIs, except that a native
/// app's loopback redirect may use any port when it was registered without
/// one. Fragments are never allowed.
pub fn matches_registered(registered: &[String], requested: &str) -> bool {
    if requested.contains('#') {
        return false;
    }
    if registered.iter().any(|r| r == requested) {
        return true;
    }
    strip_loopback_port(requested).is_some_and(|portless| registered.contains(&portless))
}

/// `http://127.0.0.1:53124/cb` → `http://127.0.0.1/cb`; `None` if `uri` is
/// not a loopback URI with an explicit numeric port.
fn strip_loopback_port(uri: &str) -> Option<String> {
    LOOPBACK_PREFIXES.iter().find_map(|prefix| {
        let rest = uri.strip_prefix(prefix)?.strip_prefix(':')?;
        let port_len = rest.bytes().take_while(u8::is_ascii_digit).count();
        let (port, tail) = rest.split_at_checked(port_len)?;
        let valid_port = !port.is_empty() && port.parse::<u16>().is_ok();
        let tail_ok = tail.is_empty() || tail.starts_with(['/', '?']);
        (valid_port && tail_ok).then(|| format!("{prefix}{tail}"))
    })
}

/// Appends query parameters to a (validated) redirect URI.
pub fn with_params(base: &str, params: &[(&str, &str)]) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        query.append_pair(key, value);
    }
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}{}", query.finish())
}

/// RFC 6749 §4.1.2.1 error redirect (+ RFC 9207 `iss`).
pub fn error_url(
    redirect_uri: &str,
    code: ErrorCode,
    description: &str,
    state: Option<&str>,
    issuer: &str,
) -> String {
    let mut params = vec![("error", code.as_str()), ("error_description", description)];
    if let Some(state) = state {
        params.push(("state", state));
    }
    params.push(("iss", issuer));
    with_params(redirect_uri, &params)
}

/// 302 to `location` (URLs we built are always valid header values).
pub fn found(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(uris: &[&str]) -> Vec<String> {
        uris.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn exact_match_only() {
        let r = reg(&["https://app.example/cb", "https://app.example/cb?x=1"]);
        assert!(matches_registered(&r, "https://app.example/cb"));
        assert!(matches_registered(&r, "https://app.example/cb?x=1"));
        for bad in [
            "https://app.example/cb/",
            "https://app.example/CB",
            "https://app.example/cb?x=2",
            "https://app.example:443/cb",
            "https://app.example/cb#frag",
            "https://evil.example/cb",
        ] {
            assert!(!matches_registered(&r, bad), "{bad}");
        }
    }

    #[test]
    fn loopback_any_port_when_registered_without_port() {
        let r = reg(&["http://127.0.0.1/callback", "http://[::1]/cb"]);
        assert!(matches_registered(&r, "http://127.0.0.1:53124/callback"));
        assert!(matches_registered(&r, "http://127.0.0.1/callback"));
        assert!(matches_registered(&r, "http://[::1]:8080/cb"));
        assert!(!matches_registered(&r, "http://127.0.0.1:53124/other"));
        assert!(!matches_registered(&r, "http://127.0.0.1:99999/callback"));
        assert!(!matches_registered(&r, "http://127.0.0.1:/callback"));
        assert!(!matches_registered(&r, "http://localhost:8080/callback"));
        assert!(!matches_registered(&r, "https://127.0.0.1:443/callback"));
        assert!(!matches_registered(&r, "http://127.0.0.1:80@evil/callback"));
        // Registered with a port: only that port.
        let r = reg(&["http://127.0.0.1:8080/cb"]);
        assert!(matches_registered(&r, "http://127.0.0.1:8080/cb"));
        assert!(!matches_registered(&r, "http://127.0.0.1:9090/cb"));
    }

    #[test]
    fn builds_query() {
        assert_eq!(
            with_params("https://a/cb", &[("code", "x y"), ("state", "s&t")]),
            "https://a/cb?code=x+y&state=s%26t"
        );
        assert_eq!(
            with_params("https://a/cb?k=v", &[("code", "c")]),
            "https://a/cb?k=v&code=c"
        );
        let url = error_url(
            "https://a/cb",
            ErrorCode::AccessDenied,
            "no",
            Some("st"),
            "https://id/t",
        );
        assert_eq!(
            url,
            "https://a/cb?error=access_denied&error_description=no&state=st&iss=https%3A%2F%2Fid%2Ft"
        );
    }
}
