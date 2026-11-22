//! Scope parsing (Entra v2 rules): the OIDC scopes plus scopes of at most ONE
//! resource app, written `{resource}/{value}` where `{resource}` is the app's
//! `identifier_uri` or `api://{client_id}`. `{resource}/.default` means "the
//! delegated scopes the client registered as required permissions" (or, for
//! client credentials, "the app roles assigned to me").

use anyhow::Context;
use entity::{app_required_permissions, app_scopes, applications};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use uuid::Uuid;

/// `groups` releases nothing by itself: whether ID tokens / userinfo carry
/// groups is the client app's `id_token_groups`. It is known so clients
/// that always ask for it (Headlamp, Grafana, ArgoCD) aren't refused.
pub const OIDC_SCOPES: [&str; 5] = ["openid", "profile", "email", "offline_access", "groups"];
pub const DEFAULT: &str = ".default";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RequestedScopes {
    pub oidc: Vec<String>,
    /// `(resource prefix, values)`; values may be exactly `[".default"]`.
    pub resource: Option<(String, Vec<String>)>,
}

/// RFC 6749 §3.3 scope-token characters.
fn valid_token(token: &str) -> bool {
    token
        .bytes()
        .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}

pub fn parse(raw: &str) -> Result<RequestedScopes, String> {
    let mut out = RequestedScopes::default();
    for token in raw.split_ascii_whitespace() {
        if !valid_token(token) {
            return Err("scope contains invalid characters".into());
        }
        if OIDC_SCOPES.contains(&token) {
            if !out.oidc.iter().any(|s| s == token) {
                out.oidc.push(token.to_owned());
            }
            continue;
        }
        // identifier URIs may themselves contain '/', the value never does.
        let Some((prefix, value)) = token.rsplit_once('/').filter(|(p, v)| {
            !p.is_empty() && !v.is_empty() && !p.ends_with(':') && !p.ends_with('/')
        }) else {
            return Err(format!("unknown scope `{token}`"));
        };
        match &mut out.resource {
            None => out.resource = Some((prefix.to_owned(), vec![value.to_owned()])),
            Some((existing, _)) if existing != prefix => {
                return Err("scopes for more than one resource requested".into());
            }
            Some((_, values)) => {
                if !values.iter().any(|v| v == value) {
                    values.push(value.to_owned());
                }
            }
        }
    }
    if let Some((_, values)) = &out.resource
        && values.len() > 1
        && values.iter().any(|v| v == DEFAULT)
    {
        return Err(".default cannot be combined with other scopes of the resource".into());
    }
    Ok(out)
}

/// The audience string of a resource app: its identifier URI, or
/// `api://{client_id}` when it has none.
pub fn audience(app: &applications::Model) -> String {
    app.identifier_uri
        .clone()
        .unwrap_or_else(|| format!("api://{}", app.client_id))
}

/// Finds the resource app a scope prefix / audience names: an exact
/// `identifier_uri` match first, then `api://{client_id}`. Unambiguous
/// because the schema only lets an app claim `api://X` when X is its own
/// client id (`applications_api_uri_is_own_client_id`).
pub async fn find_resource(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    prefix: &str,
) -> anyhow::Result<Option<applications::Model>> {
    let by_uri = applications::Entity::find()
        .filter(applications::Column::TenantId.eq(tenant_id))
        .filter(applications::Column::IdentifierUri.eq(prefix))
        .one(conn)
        .await
        .context("looking up resource app")?;
    if by_uri.is_some() {
        return Ok(by_uri);
    }
    let Some(client_id) = prefix.strip_prefix("api://") else {
        return Ok(None);
    };
    applications::Entity::find()
        .filter(applications::Column::TenantId.eq(tenant_id))
        .filter(applications::Column::ClientId.eq(client_id))
        .one(conn)
        .await
        .context("looking up resource app")
}

/// Expands `.default` and checks every value is a scope the resource
/// exposes. `Ok(None)` = some value is unknown.
pub async fn resolve_delegated(
    conn: &impl ConnectionTrait,
    client_app_id: Uuid,
    resource: &applications::Model,
    values: &[String],
) -> anyhow::Result<Option<Vec<app_scopes::Model>>> {
    let exposed = app_scopes::Entity::find()
        .filter(app_scopes::Column::ApplicationId.eq(resource.id))
        .all(conn)
        .await
        .context("loading resource scopes")?;
    if values.iter().any(|v| v == DEFAULT) {
        let required: Vec<Uuid> = app_required_permissions::Entity::find()
            .filter(app_required_permissions::Column::ApplicationId.eq(client_app_id))
            .filter(app_required_permissions::Column::ResourceApplicationId.eq(resource.id))
            .all(conn)
            .await
            .context("loading required permissions")?
            .into_iter()
            .filter_map(|p| p.scope_id)
            .collect();
        return Ok(Some(
            exposed
                .into_iter()
                .filter(|s| required.contains(&s.id))
                .collect(),
        ));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        match exposed.iter().find(|s| &s.value == value) {
            Some(scope) => out.push(scope.clone()),
            None => return Ok(None),
        }
    }
    Ok(Some(out))
}

/// The validated `scope` of an interactive request (authorize, device
/// authorization): OIDC scopes plus the one resource's expanded values.
#[derive(Debug, PartialEq, Eq)]
pub struct Resolved {
    pub oidc: Vec<String>,
    pub resource_id: Option<Uuid>,
    /// Never `.default`: already expanded.
    pub resource_scopes: Vec<String>,
}

/// Parses and resolves `raw` for `client`. `Ok(Err(description))` =
/// `invalid_scope`; at least one scope is required.
pub async fn resolve_request(
    conn: &impl ConnectionTrait,
    client: &applications::Model,
    raw: &str,
) -> anyhow::Result<Result<Resolved, String>> {
    let requested = match parse(raw) {
        Ok(r) if r.oidc.is_empty() && r.resource.is_none() => {
            return Ok(Err("scope is required".into()));
        }
        Ok(r) => r,
        Err(msg) => return Ok(Err(msg)),
    };
    let (resource_id, resource_scopes) = match &requested.resource {
        None => (None, Vec::new()),
        Some((prefix, values)) => {
            let Some(resource) = find_resource(conn, client.tenant_id, prefix).await? else {
                return Ok(Err("unknown resource".into()));
            };
            let Some(scopes) = resolve_delegated(conn, client.id, &resource, values).await? else {
                return Ok(Err("the resource does not expose a requested scope".into()));
            };
            (
                Some(resource.id),
                scopes.into_iter().map(|s| s.value).collect(),
            )
        }
    };
    Ok(Ok(Resolved {
        oidc: requested.oidc,
        resource_id,
        resource_scopes,
    }))
}

/// The scope values `resource_id` currently exposes.
pub async fn exposed_values(
    conn: &impl ConnectionTrait,
    resource_id: Uuid,
) -> anyhow::Result<Vec<String>> {
    Ok(app_scopes::Entity::find()
        .filter(app_scopes::Column::ApplicationId.eq(resource_id))
        .all(conn)
        .await
        .context("loading resource scopes")?
        .into_iter()
        .map(|s| s.value)
        .collect())
}

/// Splits stored grant scopes (codes / refresh tokens keep OIDC scopes and
/// bare resource values in one list) into `(oidc, resource values)`.
pub fn split_stored(scopes: &[String]) -> (Vec<String>, Vec<String>) {
    scopes
        .iter()
        .cloned()
        .partition(|s| OIDC_SCOPES.contains(&s.as_str()))
}

/// Space-separated granted scopes as reported in token responses:
/// OIDC scopes bare, resource scopes fully qualified.
pub fn granted_string(oidc: &[String], audience: Option<&str>, values: &[String]) -> String {
    let mut parts: Vec<String> = values
        .iter()
        .filter_map(|v| audience.map(|aud| format!("{aud}/{v}")))
        .collect();
    parts.extend(oidc.iter().cloned());
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn oidc_only() {
        let p = parse("openid  profile openid email offline_access groups").unwrap();
        assert_eq!(
            p.oidc,
            s(&["openid", "profile", "email", "offline_access", "groups"])
        );
        assert_eq!(p.resource, None);
        assert_eq!(parse("").unwrap(), RequestedScopes::default());
    }

    #[test]
    fn one_resource_split_from_oidc() {
        let p = parse("openid api://orders/Orders.Read api://orders/Orders.Write").unwrap();
        assert_eq!(p.oidc, s(&["openid"]));
        assert_eq!(
            p.resource,
            Some(("api://orders".into(), s(&["Orders.Read", "Orders.Write"])))
        );
        // Identifier URIs with paths split at the last '/'.
        let p = parse("https://api.contoso.com/orders/read").unwrap();
        assert_eq!(
            p.resource,
            Some(("https://api.contoso.com/orders".into(), s(&["read"])))
        );
        let p = parse("api://orders/.default").unwrap();
        assert_eq!(p.resource, Some(("api://orders".into(), s(&[DEFAULT]))));
    }

    #[test]
    fn rejects_bad_scopes() {
        for bad in [
            "api://a/x api://b/y",
            "unknown",
            "api://a/",
            "/x",
            "api://a/.default api://a/x",
            "https://x",
            "openid \"quoted\"",
            "a\\b/c",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn stored_groups_scope_is_oidc() {
        let (oidc, values) = split_stored(&s(&["openid", "groups", "Orders.Read"]));
        assert_eq!(oidc, s(&["openid", "groups"]));
        assert_eq!(values, s(&["Orders.Read"]));
    }

    #[test]
    fn granted_scope_string() {
        assert_eq!(
            granted_string(&s(&["openid"]), Some("api://o"), &s(&["r", "w"])),
            "api://o/r api://o/w openid"
        );
        assert_eq!(
            granted_string(&s(&["openid", "email"]), None, &[]),
            "openid email"
        );
    }
}
