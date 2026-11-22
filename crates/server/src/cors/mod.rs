//! CORS for cross-origin SPAs on the protocol endpoints an SPA needs
//! (discovery, JWKS, token, revoke, userinfo) — never on the login or
//! management APIs. Contract: `docs/architecture.md` (CORS).
//!
//! An app's effective allowed origins are its explicit `web_origins` plus,
//! for a public client, the origins of its redirect URIs (computed on every
//! request, never stored). Origins are compared as exact strings in the
//! browser's serialization (`scheme://host[:port]`, lowercase, default
//! port omitted), which [`validate_origin`] enforces on input.

mod http;

use anyhow::Context;
use entity::{applications, enums::ClientType};
use sea_orm::{ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter, sea_query::Expr};
use uuid::Uuid;

pub use http::{for_client, preflight_get, preflight_get_post, preflight_post, tenant_wide};

const MAX_ORIGIN_LEN: usize = 512;
const LOOPBACK_HOSTS: [&str; 2] = ["127.0.0.1", "[::1]"];

/// A web origin as a browser serializes it in `Origin`: `https://host[:port]`
/// or `http://127.0.0.1[:port]` / `http://[::1][:port]` (the loopback rule
/// of redirect URIs). Lowercase, no default port, no path, query, fragment,
/// userinfo or wildcard; https hosts are DNS names or IPv4 literals
/// (internationalized names in punycode).
pub fn validate_origin(origin: &str) -> Result<(), String> {
    let invalid = || {
        format!(
            "`{}` is not a valid web origin: use scheme://host[:port] with a lowercase \
             https scheme and host (plain http only for 127.0.0.1 / [::1]), no path, \
             trailing slash, query, fragment or wildcard, and no default port",
            origin.escape_debug()
        )
    };
    if origin.len() > MAX_ORIGIN_LEN || !origin.is_ascii() {
        return Err(invalid());
    }
    let (scheme, authority) = origin.split_once("://").ok_or_else(invalid)?;
    let default_port = match scheme {
        "https" => 443,
        "http" => 80,
        _ => return Err(invalid()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.contains(']') => (host, Some(port)),
        _ => (authority, None),
    };
    let port_ok = port.is_none_or(|p| {
        !p.starts_with('0')
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().is_ok_and(|n| n != default_port)
    });
    let host_ok = match scheme {
        "http" => LOOPBACK_HOSTS.contains(&host),
        _ => dns_host(host),
    };
    if port_ok && host_ok {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// Lowercase dot-separated labels of `a-z 0-9 -`, none empty or with a
/// leading / trailing `-`.
fn dns_host(host: &str) -> bool {
    (1..=253).contains(&host.len())
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The origin a browser reports for pages under a (validated) redirect URI,
/// or `None` when it has none we would accept (custom schemes, IPv6 https
/// hosts, …). The host is lowercased and a default port dropped, as a
/// browser serializes it.
pub fn origin_of(redirect_uri: &str) -> Option<String> {
    let (scheme, rest) = redirect_uri.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    let default = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => return None,
    };
    let authority = authority.strip_suffix(default).unwrap_or(&authority);
    let origin = format!("{scheme}://{authority}");
    validate_origin(&origin).is_ok().then_some(origin)
}

/// The app's effective allowed origins: explicit first, then (public
/// clients only — the SPAs) its redirect URIs' origins, deduplicated.
pub fn effective_origins(app: &applications::Model) -> Vec<String> {
    let mut out = app.web_origins.clone();
    if app.client_type == ClientType::Public {
        for origin in app.redirect_uris.iter().filter_map(|uri| origin_of(uri)) {
            if !out.contains(&origin) {
                out.push(origin);
            }
        }
    }
    out
}

pub fn allows(app: &applications::Model, origin: &str) -> bool {
    effective_origins(app).iter().any(|o| o == origin)
}

/// True if any app of the tenant allows `origin`.
pub async fn tenant_allows(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    origin: &str,
) -> anyhow::Result<bool> {
    if validate_origin(origin).is_err() {
        return Ok(false);
    }
    // Unauthenticated callers choose `origin`, so let SQL return only rows
    // that can allow it: an explicit entry, or a public client with a
    // redirect URI starting with it (`starts_with`: a literal prefix, no
    // pattern). `origin_of` only lowercases the authority and drops a
    // default port, so every URI whose origin matches has it as a
    // case-insensitive prefix; `allows` below stays the exact check.
    let apps = applications::Entity::find()
        .filter(applications::Column::TenantId.eq(tenant_id))
        .filter(
            Condition::any()
                .add(Expr::cust_with_values("$1 = ANY(web_origins)", [origin]))
                .add(
                    Condition::all()
                        .add(applications::Column::ClientType.eq(ClientType::Public))
                        .add(Expr::cust_with_values(
                            "EXISTS (SELECT 1 FROM unnest(redirect_uris) AS r(uri) \
                             WHERE starts_with(lower(r.uri), $1))",
                            [origin],
                        )),
                ),
        )
        .all(conn)
        .await
        .context("loading the tenant's allowed origins")?;
    Ok(apps.iter().any(|app| allows(app, origin)))
}

#[cfg(test)]
mod tests {
    use entity::enums::{AccessTokenFormat, GroupsClaimFormat, SigningAlg};

    use super::*;

    #[test]
    fn origins_must_be_serialized_exactly() {
        for ok in [
            "https://app.example",
            "https://app.example:8443",
            "https://xn--bcher-kva.example",
            "https://192.0.2.1",
            "http://127.0.0.1",
            "http://127.0.0.1:5173",
            "http://[::1]:8080",
        ] {
            assert!(validate_origin(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "null",
            "app.example",
            "https://",
            "https://app.example/",
            "https://app.example/cb",
            "https://app.example?x",
            "https://app.example#x",
            "https://*.app.example",
            "https://App.example",
            "HTTPS://app.example",
            "https://app.example:443",
            "http://127.0.0.1:80",
            "https://app.example:0",
            "https://app.example:08443",
            "https://app.example:99999",
            "https://app.example:",
            "https://user@app.example",
            "http://app.example",
            "http://localhost:5173",
            "http://127.0.0.1.evil.example",
            "https://-app.example",
            "https://app..example",
            "https://bücher.example",
            "https://[::1]",
            "wss://app.example",
            "https://app.example ",
        ] {
            assert!(validate_origin(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn redirect_uri_origins() {
        let cases = [
            ("https://app.example/cb", Some("https://app.example")),
            (
                "https://App.Example:443/cb?x=1",
                Some("https://app.example"),
            ),
            ("https://app.example:8443", Some("https://app.example:8443")),
            ("http://127.0.0.1/cb", Some("http://127.0.0.1")),
            ("http://[::1]:53124/cb", Some("http://[::1]:53124")),
            ("com.example.app:/cb", None),
            ("https://[2001:db8::1]/cb", None),
        ];
        for (uri, want) in cases {
            assert_eq!(origin_of(uri).as_deref(), want, "{uri}");
        }
    }

    fn app(client_type: ClientType, explicit: &[&str]) -> applications::Model {
        let now = chrono::Utc::now().fixed_offset();
        applications::Model {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            client_id: "x".into(),
            display_name: "x".into(),
            client_type,
            builtin: false,
            redirect_uris: vec![
                "https://spa.example/cb".into(),
                "https://spa.example/b".into(),
            ],
            post_logout_redirect_uris: vec!["https://bye.example/".into()],
            web_origins: explicit.iter().map(|s| (*s).to_owned()).collect(),
            identifier_uri: None,
            access_token_format: AccessTokenFormat::Jwt,
            signing_alg: SigningAlg::Rs256,
            groups_claim_format: GroupsClaimFormat::Id,
            id_token_groups: entity::enums::IdTokenGroups::None,
            assignment_required: false,
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 3600,
            device_code_enabled: false,
            mfa_policy: entity::enums::AppMfaPolicy::Inherit,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn effective_is_explicit_union_public_redirect_origins() {
        let public = app(ClientType::Public, &["https://other.example"]);
        assert_eq!(
            effective_origins(&public),
            ["https://other.example", "https://spa.example"]
        );
        assert!(allows(&public, "https://spa.example"));
        assert!(
            !allows(&public, "https://bye.example"),
            "post-logout URIs don't count"
        );
        let confidential = app(ClientType::Confidential, &["https://other.example"]);
        assert_eq!(effective_origins(&confidential), ["https://other.example"]);
        assert!(!allows(&confidential, "https://spa.example"));
    }
}
