//! Input validation for app registrations: client ids, redirect URIs,
//! identifier URIs and permission (scope / role) values. Errors are 400s
//! whose message is safe to echo.

use crate::{
    directory::reject_control_chars,
    error::{AppError, AppResult},
    oidc::scope::{DEFAULT, OIDC_SCOPES},
};

const MAX_URI_LEN: usize = 2048;
pub const MAX_REDIRECT_URIS: usize = 32;
const MAX_DESCRIPTION: usize = 1024;

fn bad(msg: impl Into<String>) -> AppError {
    AppError::BadRequest(msg.into())
}

/// `client_id`: 1-128 of `A-Z a-z 0-9 . _ -`, starting alphanumeric. It is
/// sent in Basic auth (no `:`), embedded in `api://{client_id}` and scope
/// strings (no `/` or spaces).
pub fn client_id(id: &str) -> AppResult<()> {
    let ok = (1..=128).contains(&id.len())
        && id.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(bad(
            "client_id must be 1-128 characters of A-Z, a-z, 0-9, '.', '_', '-', starting with a letter or digit",
        ))
    }
}

/// Redirect / post-logout URI: absolute `https://` with a host, or plain
/// `http://` to an IP loopback (`127.0.0.1`, `[::1]`; RFC 8252 §7.3 — not
/// `localhost`, which may resolve off-host). No fragment, no userinfo.
pub fn redirect_uri(uri: &str) -> Result<(), String> {
    if uri.len() > MAX_URI_LEN || uri.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!(
            "`{}` is not a valid redirect URI",
            uri.escape_debug()
        ));
    }
    if uri.contains('#') {
        return Err(format!("redirect URI `{uri}` must not contain a fragment"));
    }
    let rest = if let Some(rest) = uri.strip_prefix("https://") {
        rest
    } else if let Some(rest) = uri.strip_prefix("http://") {
        // The loopback literal must end the host: `[::1].evil.example` and
        // `127.0.0.1.evil.example` are other hosts.
        let is_loopback = ["127.0.0.1", "[::1]"].iter().any(|host| {
            rest.strip_prefix(host)
                .is_some_and(|tail| tail.is_empty() || tail.starts_with([':', '/', '?']))
        });
        if !is_loopback {
            return Err(format!(
                "redirect URI `{uri}` must use https (plain http only for 127.0.0.1 / [::1])"
            ));
        }
        rest
    } else {
        return Err(format!(
            "redirect URI `{uri}` must be an absolute https:// URI (lowercase scheme)"
        ));
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains(['@', '\\']) || authority.starts_with(':') {
        return Err(format!("redirect URI `{uri}` has an invalid host"));
    }
    if let Some((_, port)) = authority
        .rsplit_once(':')
        .filter(|_| !authority.ends_with(']'))
        && port.parse::<u16>().is_err()
    {
        return Err(format!("redirect URI `{uri}` has an invalid port"));
    }
    Ok(())
}

/// A list of redirect URIs: each valid, no duplicates, bounded.
pub fn redirect_uris(uris: &[String], what: &str) -> AppResult<()> {
    if uris.len() > MAX_REDIRECT_URIS {
        return Err(bad(format!(
            "at most {MAX_REDIRECT_URIS} {what} are allowed"
        )));
    }
    for (i, uri) in uris.iter().enumerate() {
        redirect_uri(uri).map_err(bad)?;
        if uris.iter().skip(i + 1).any(|other| other == uri) {
            return Err(bad(format!("duplicate {what} entry `{uri}`")));
        }
    }
    Ok(())
}

/// RFC 6749 §3.3 scope-token characters (mirrors the DB CHECK).
fn scope_token_chars(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}

/// `identifier_uri` (the audience). `api://X` only for the app's own
/// `client_id` (DB CHECK `applications_api_uri_is_own_client_id`), with a
/// lowercase scheme; otherwise an `https://` URI. Scope strings are
/// `{identifier_uri}/{value}`, so it must consist of scope-token
/// characters and not end in `/`.
pub fn identifier_uri(uri: &str, own_client_id: &str) -> AppResult<()> {
    if uri.len() > 256 || !scope_token_chars(uri) || uri.ends_with('/') {
        return Err(bad(
            "identifier_uri must be at most 256 printable characters (no spaces, quotes or \
             backslashes) and must not end with '/'",
        ));
    }
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("api://") {
        if !uri.starts_with("api://") {
            return Err(bad("identifier_uri scheme must be lowercase `api://`"));
        }
        if uri != format!("api://{own_client_id}") {
            return Err(bad(format!(
                "an `api://` identifier_uri must be `api://{own_client_id}` (the app's own client_id)"
            )));
        }
        return Ok(());
    }
    if !uri.starts_with("https://") || uri.contains(['#', '?']) || uri.len() <= "https://".len() {
        return Err(bad(
            "identifier_uri must be `api://{client_id}` or an https:// URI without query or fragment",
        ));
    }
    Ok(())
}

/// A scope or app role `value`: 1-120 scope-token characters, no `/` (the
/// separator in `{resource}/{value}`).
pub fn permission_value(value: &str, what: &str) -> AppResult<()> {
    if value.is_empty() || value.len() > 120 || !scope_token_chars(value) || value.contains('/') {
        return Err(bad(format!(
            "{what} value must be 1-120 printable characters without spaces, quotes, '\\' or '/'"
        )));
    }
    Ok(())
}

/// Scope values must not shadow the OIDC scopes or `.default`: stored grants
/// keep OIDC scopes and resource values in one list
/// (`oidc::scope::split_stored`).
pub fn scope_value(value: &str) -> AppResult<()> {
    permission_value(value, "scope")?;
    let reserved = OIDC_SCOPES
        .iter()
        .chain(std::iter::once(&DEFAULT))
        .any(|r| r.eq_ignore_ascii_case(value));
    if reserved {
        return Err(bad(format!("scope value `{value}` is reserved")));
    }
    Ok(())
}

/// An optional [`description`]; absent or blank → `None`.
pub fn opt_description(raw: Option<&str>) -> AppResult<Option<String>> {
    Ok(raw.map(description).transpose()?.filter(|d| !d.is_empty()))
}

/// Free-text description: trimmed, single line, bounded.
pub fn description(raw: &str) -> AppResult<String> {
    let text = raw.trim();
    reject_control_chars(text, "description")?;
    if text.chars().count() > MAX_DESCRIPTION {
        return Err(bad(format!(
            "description must be at most {MAX_DESCRIPTION} characters"
        )));
    }
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uris_https_or_ip_loopback() {
        for ok in [
            "https://app.example/cb",
            "https://app.example:8443/cb?x=1",
            "https://app.example",
            "http://127.0.0.1/cb",
            "http://127.0.0.1:8080/cb",
            "http://[::1]/cb",
            "http://[::1]:53124",
        ] {
            assert!(redirect_uri(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "/cb",
            "app.example/cb",
            "http://app.example/cb",
            "http://localhost:3000/cb",
            "http://127.0.0.1.evil.example/cb",
            "http://[::1].evil.com/cb",
            "http://[::1]evil/cb",
            "http://[::1]@evil/cb",
            "http://127.0.0.1@evil/cb",
            "http://127.0.0.10/cb",
            "HTTPS://app.example/cb",
            "https://app.example/cb#frag",
            "https://user@app.example/cb",
            "https:///cb",
            "https://:443/cb",
            "https://app.example:99999/cb",
            "https://app.example/c b",
            "https://app.example/\ncb",
            "javascript:alert(1)",
            "com.example.app:/cb",
        ] {
            assert!(redirect_uri(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn redirect_uri_lists_reject_duplicates_and_bloat() {
        let a = "https://a.example/cb".to_owned();
        assert!(redirect_uris(std::slice::from_ref(&a), "redirect_uris").is_ok());
        assert!(redirect_uris(&[a.clone(), a.clone()], "redirect_uris").is_err());
        let many: Vec<String> = (0..=MAX_REDIRECT_URIS)
            .map(|i| format!("https://a.example/{i}"))
            .collect();
        assert!(redirect_uris(&many, "redirect_uris").is_err());
    }

    #[test]
    fn identifier_uri_rules() {
        assert!(identifier_uri("api://orders", "orders").is_ok());
        assert!(identifier_uri("https://api.contoso.com/orders", "orders").is_ok());
        for (uri, why) in [
            ("api://other", "foreign client id"),
            ("API://orders", "uppercase scheme"),
            ("Api://orders", "mixed-case scheme"),
            ("api://orders/", "trailing slash"),
            ("https://x.example/a b", "space"),
            ("https://x.example/?q", "query"),
            ("http://x.example", "plain http"),
            ("urn:x", "other scheme"),
        ] {
            assert!(identifier_uri(uri, "orders").is_err(), "{why}: {uri}");
        }
    }

    #[test]
    fn scope_values_are_tokens_and_not_reserved() {
        assert!(scope_value("Orders.Read").is_ok());
        for bad in [
            "",
            "a b",
            "a/b",
            "a\"b",
            "openid",
            "OpenID",
            "profile",
            "email",
            "offline_access",
            ".default",
            &"x".repeat(121),
        ] {
            assert!(scope_value(bad).is_err(), "{bad:?}");
        }
        // Roles may be named like OIDC scopes; they never mix with them.
        assert!(permission_value("email", "role").is_ok());
    }

    #[test]
    fn client_ids() {
        for ok in ["web-app", "a", "App_1.2"] {
            assert!(client_id(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-x", "a:b", "a/b", "a b", "é", &"x".repeat(129)] {
            assert!(client_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn descriptions() {
        assert_eq!(description("  hi ").unwrap(), "hi");
        assert!(description("a\nb").is_err());
        assert!(description(&"x".repeat(1025)).is_err());
    }
}
