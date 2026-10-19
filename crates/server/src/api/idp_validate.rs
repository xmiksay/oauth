//! Validation of identity-provider fields (pure).

use entity::enums::{IdpClientAuth, IdpPolicy};
use sea_orm::ActiveEnum;

use super::validate::scope_token_chars;
use crate::{error::AppError, federation::urls};

const MAX_NAME: usize = 64;
const MAX_URL: usize = 2048;
const MAX_CLIENT_ID: usize = 512;
const MAX_SECRET: usize = 1024;
const MAX_SCOPES: usize = 20;
const MAX_DOMAINS: usize = 50;

fn bad(msg: impl Into<String>) -> AppError {
    AppError::BadRequest(msg.into())
}

fn text(raw: &str, max: usize, what: &str) -> Result<String, AppError> {
    let value = raw.trim();
    if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(bad(format!(
            "{what} must be 1-{max} characters without control characters"
        )));
    }
    Ok(value.to_owned())
}

pub fn name(raw: &str) -> Result<String, AppError> {
    text(raw, MAX_NAME, "name")
}

pub fn client_id(raw: &str) -> Result<String, AppError> {
    text(raw, MAX_CLIENT_ID, "client_id")
}

/// Kept exactly as given (no trimming): it is the provider's secret.
pub fn client_secret(raw: &str) -> Result<String, AppError> {
    if raw.is_empty() || raw.len() > MAX_SECRET || raw.chars().any(char::is_control) {
        return Err(bad(format!(
            "client_secret must be 1-{MAX_SECRET} bytes without control characters"
        )));
    }
    Ok(raw.to_owned())
}

pub fn mfa_acr(raw: &str) -> Result<String, AppError> {
    text(raw, 256, "mfa_acr")
}

/// An `https://` URL without query or fragment (`http://` only to loopback
/// in development). The issuer is compared byte for byte with the
/// provider's, so it is stored as given.
pub fn url(raw: &str, what: &str, allow_http_loopback: bool) -> Result<String, AppError> {
    let ok = raw.len() <= MAX_URL
        && urls::checked(raw, allow_http_loopback).is_some_and(|u| u.query().is_none());
    if !ok {
        return Err(bad(format!(
            "{what} must be an https URL without query or fragment"
        )));
    }
    Ok(raw.to_owned())
}

pub fn client_auth(raw: &str) -> Result<IdpClientAuth, AppError> {
    IdpClientAuth::try_from_value(&raw.to_owned())
        .map_err(|_| bad("client_auth must be `post` or `basic`"))
}

pub fn policy(raw: &str) -> Result<IdpPolicy, AppError> {
    IdpPolicy::try_from_value(&raw.to_owned())
        .map_err(|_| bad("policy must be `jit`, `link_only` or `deny`"))
}

/// Distinct scope tokens including `openid`.
pub fn scopes(raw: &[String]) -> Result<Vec<String>, AppError> {
    let mut out: Vec<String> = Vec::new();
    for scope in raw {
        if scope.is_empty() || scope.len() > 128 || !scope_token_chars(scope) {
            return Err(bad("scopes must be RFC 6749 scope tokens"));
        }
        if !out.contains(scope) {
            out.push(scope.clone());
        }
    }
    if out.len() > MAX_SCOPES {
        return Err(bad(format!("at most {MAX_SCOPES} scopes")));
    }
    if !out.iter().any(|s| s == "openid") {
        return Err(bad("scopes must include `openid`"));
    }
    Ok(out)
}

fn dns_name(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    name.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Lower-cased, distinct DNS names (home-realm discovery domains).
pub fn email_domains(raw: &[String]) -> Result<Vec<String>, AppError> {
    let mut out: Vec<String> = Vec::new();
    for domain in raw {
        let domain = domain.trim().to_ascii_lowercase();
        if !dns_name(&domain) {
            return Err(bad(format!(
                "`{}` is not a DNS name",
                domain.escape_debug()
            )));
        }
        if !out.contains(&domain) {
            out.push(domain);
        }
    }
    if out.len() > MAX_DOMAINS {
        return Err(bad(format!("at most {MAX_DOMAINS} email domains")));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn urls() {
        assert!(url("https://idp.example", "issuer", false).is_ok());
        assert!(url("https://idp.example/tenant/v2.0", "issuer", false).is_ok());
        assert!(url("http://idp.example", "issuer", false).is_err());
        assert!(url("https://idp.example/?x=1", "issuer", false).is_err());
        assert!(url("http://127.0.0.1:9000", "issuer", false).is_err());
        assert!(url("http://127.0.0.1:9000", "issuer", true).is_ok());
        assert!(
            url(
                &format!("https://x.example/{}", "a".repeat(2048)),
                "issuer",
                false
            )
            .is_err()
        );
    }

    #[test]
    fn scopes_need_openid() {
        assert_eq!(
            scopes(&strings(&["openid", "email", "openid"])).unwrap(),
            ["openid", "email"]
        );
        assert!(scopes(&strings(&["email"])).is_err());
        assert!(scopes(&strings(&["openid", "a b"])).is_err());
        assert!(scopes(&strings(&["openid", ""])).is_err());
    }

    #[test]
    fn domains_are_dns_names() {
        assert_eq!(
            email_domains(&strings(&[" Contoso.COM ", "contoso.com", "a-b.example"])).unwrap(),
            ["contoso.com", "a-b.example"]
        );
        for bad in [
            "localhost",
            "-a.example",
            "a..example",
            "a_b.example",
            "*.example",
            "",
        ] {
            assert!(email_domains(&strings(&[bad])).is_err(), "{bad}");
        }
    }

    #[test]
    fn enums_and_text() {
        assert_eq!(policy("jit").unwrap(), IdpPolicy::Jit);
        assert!(policy("auto").is_err());
        assert_eq!(client_auth("basic").unwrap(), IdpClientAuth::Basic);
        assert!(client_auth("private_key_jwt").is_err());
        assert_eq!(name("  Contoso SSO ").unwrap(), "Contoso SSO");
        assert!(name("").is_err());
        assert!(name(&"x".repeat(65)).is_err());
        assert_eq!(client_secret(" s ").unwrap(), " s ");
        assert!(client_secret("a\nb").is_err());
    }
}
