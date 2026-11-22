//! The tenant file of `oauth apply` (YAML, strict: unknown fields are
//! errors). Lists are the complete desired set of managed objects (absent =
//! empty); optional scalars left out keep the stored value (or the API's
//! default on create). Secrets never appear in the file: `*_env` fields name
//! an environment variable holding them, which must start with
//! [`ENV_PREFIX`].

use std::collections::HashSet;

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::api::{app_body::AppBody, app_body::nullable, idp_body::IdpBody};

/// Bound on the file size: it is parsed whole.
pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;

/// Every `*_env` reference must start with this. The apply process runs
/// with the server's own secrets in its environment (`OAUTH_MASTER_KEY`,
/// `DATABASE_URL`, `SMTP_URL`, `TELEGRAM_BOT_TOKEN`, …); without the prefix
/// a file author could seal one as an IdP client secret they control the
/// token endpoint of, and the server would send it there.
pub const ENV_PREFIX: &str = "OAUTH_APPLY_";

/// A `*_env` value: `OAUTH_APPLY_` + upper-case letters, digits and `_`.
fn check_env_name(var: &str, what: &str) -> anyhow::Result<()> {
    let ok = var.strip_prefix(ENV_PREFIX).is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    });
    if !ok {
        bail!(
            "{what}: environment variable `{var}` must be named `{ENV_PREFIX}` followed by \
             A-Z, 0-9 or `_` (the server's own variables are never read)"
        );
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    /// Slug of an existing tenant (`oauth bootstrap --tenant` creates one).
    pub tenant: String,
    #[serde(default)]
    pub users: Vec<UserSpec>,
    #[serde(default)]
    pub groups: Vec<GroupSpec>,
    #[serde(default)]
    pub identity_providers: Vec<IdpSpec>,
    #[serde(default)]
    pub applications: Vec<AppSpec>,
    #[serde(default)]
    pub directory_roles: Vec<DirectoryRoleSpec>,
    #[serde(default)]
    pub role_assignments: Vec<RoleAssignmentSpec>,
    #[serde(default)]
    pub admin_consents: Vec<ConsentSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSpec {
    pub email: String,
    pub display_name: String,
    /// Environment variable (`OAUTH_APPLY_…`) with the initial password
    /// (only used when the user is created; without it the user has no
    /// password).
    pub password_env: Option<String>,
    /// Only with `password_env`, honored on create only; default true (like
    /// the API: the user replaces the initial password at first sign-in).
    pub must_change_password: Option<bool>,
    pub disabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSpec {
    pub display_name: String,
    pub description: Option<String>,
    /// Member emails.
    #[serde(default)]
    pub members: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdpSpec {
    pub name: String,
    /// `oidc` (default), `google`, `entra` or `github`; fixed after creation.
    pub kind: Option<String>,
    /// Required for `oidc`; a preset supplies its own default.
    pub issuer: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    pub discovery_url: Option<Option<String>>,
    pub client_id: String,
    /// Environment variable (`OAUTH_APPLY_…`) with the client secret; set
    /// only while the provider has none (rotate it through the API / admin UI).
    pub client_secret_env: Option<String>,
    pub client_auth: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub policy: Option<String>,
    pub trust_upstream_mfa: Option<bool>,
    #[serde(default, deserialize_with = "nullable")]
    pub mfa_acr: Option<Option<String>>,
    pub email_domains: Option<Vec<String>>,
    #[serde(default, deserialize_with = "nullable")]
    pub hosted_domain: Option<Option<String>>,
    pub allowed_tenants: Option<Vec<String>>,
    pub trust_upstream_email: Option<bool>,
    pub enabled: Option<bool>,
    pub visible: Option<bool>,
}

impl IdpSpec {
    /// The management API body for these settings (secret handled apart).
    pub fn body(&self, secret: Option<String>) -> IdpBody {
        IdpBody {
            kind: self.kind.clone(),
            name: Some(self.name.clone()),
            issuer: self.issuer.clone(),
            discovery_url: self.discovery_url.clone(),
            client_id: Some(self.client_id.clone()),
            client_secret: secret.map(Some),
            client_auth: self.client_auth.clone(),
            scopes: self.scopes.clone(),
            policy: self.policy.clone(),
            trust_upstream_mfa: self.trust_upstream_mfa,
            mfa_acr: self.mfa_acr.clone(),
            email_domains: self.email_domains.clone(),
            hosted_domain: self.hosted_domain.clone(),
            allowed_tenants: self.allowed_tenants.clone(),
            trust_upstream_email: self.trust_upstream_email,
            enabled: self.enabled,
            visible: self.visible,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSpec {
    pub client_id: String,
    /// `confidential` (default) or `public`; fixed after creation.
    pub client_type: Option<String>,
    pub display_name: String,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub web_origins: Option<Vec<String>>,
    #[serde(default, deserialize_with = "nullable")]
    pub identifier_uri: Option<Option<String>>,
    pub access_token_format: Option<String>,
    pub signing_alg: Option<String>,
    pub groups_claim_format: Option<String>,
    /// `none` (default), `all` or `assigned`.
    pub id_token_groups: Option<String>,
    pub assignment_required: Option<bool>,
    pub access_token_ttl_secs: Option<i32>,
    pub refresh_token_ttl_secs: Option<i32>,
    pub device_code_enabled: Option<bool>,
    pub mfa_policy: Option<String>,
    /// Back-Channel Logout 1.0 endpoint; `null` clears it.
    #[serde(default, deserialize_with = "nullable")]
    pub backchannel_logout_uri: Option<Option<String>>,
    pub backchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub scopes: Vec<ScopeSpec>,
    #[serde(default)]
    pub roles: Vec<RoleSpec>,
    #[serde(default)]
    pub required_permissions: Vec<PermissionSpec>,
}

impl AppSpec {
    /// The management API body for the app's own settings.
    pub fn body(&self) -> AppBody {
        AppBody {
            client_id: None,
            client_type: None,
            display_name: Some(self.display_name.clone()),
            redirect_uris: self.redirect_uris.clone(),
            post_logout_redirect_uris: self.post_logout_redirect_uris.clone(),
            web_origins: self.web_origins.clone(),
            identifier_uri: self.identifier_uri.clone(),
            access_token_format: self.access_token_format.clone(),
            signing_alg: self.signing_alg.clone(),
            groups_claim_format: self.groups_claim_format.clone(),
            id_token_groups: self.id_token_groups.clone(),
            assignment_required: self.assignment_required,
            access_token_ttl_secs: self.access_token_ttl_secs,
            refresh_token_ttl_secs: self.refresh_token_ttl_secs,
            device_code_enabled: self.device_code_enabled,
            mfa_policy: self.mfa_policy.clone(),
            backchannel_logout_uri: self.backchannel_logout_uri.clone(),
            backchannel_logout_session_required: self.backchannel_logout_session_required,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSpec {
    pub value: String,
    pub description: Option<String>,
    pub admin_consent_required: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSpec {
    pub value: String,
    pub display_name: String,
    pub description: Option<String>,
    pub allowed_member_types: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionSpec {
    /// The resource app's `client_id`.
    pub resource: String,
    /// `delegated` (a scope) or `application` (an app role).
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRoleSpec {
    pub user: String,
    pub role: String,
}

/// An app role of `resource` assigned to exactly one principal.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleAssignmentSpec {
    pub resource: String,
    pub role: String,
    pub user: Option<String>,
    pub group: Option<String>,
    pub application: Option<String>,
}

/// Tenant-wide (admin) consent of `client` to its required permissions on
/// `resource`; both lists absent = all of them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentSpec {
    pub client: String,
    pub resource: String,
    pub scopes: Option<Vec<String>>,
    pub app_roles: Option<Vec<String>>,
}

/// Reads a tenant file, never more than [`MAX_FILE_BYTES`] + 1 bytes, so an
/// oversized file is refused without filling memory.
pub fn read_file(path: &std::path::Path) -> anyhow::Result<String> {
    use std::io::Read;
    let what = || format!("reading {}", path.display());
    let file = std::fs::File::open(path).with_context(what)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(MAX_FILE_BYTES)?.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(what)?;
    if bytes.len() > MAX_FILE_BYTES {
        bail!("{} is larger than {MAX_FILE_BYTES} bytes", path.display());
    }
    String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))
}

/// Parses and checks a tenant file.
pub fn parse(text: &str) -> anyhow::Result<Spec> {
    if text.len() > MAX_FILE_BYTES {
        bail!("the file is larger than {MAX_FILE_BYTES} bytes");
    }
    let spec: Spec = serde_yaml_ng::from_str(text).context("parsing the tenant file")?;
    spec.check()?;
    Ok(spec)
}

/// Errors on the first value seen twice (after `key`).
fn unique<'a, T>(
    items: impl IntoIterator<Item = &'a T>,
    key: impl Fn(&T) -> String,
    what: &str,
) -> anyhow::Result<()>
where
    T: 'a,
{
    let mut seen = HashSet::new();
    for item in items {
        let k = key(item);
        if !seen.insert(k.clone()) {
            bail!("duplicate {what} `{k}`");
        }
    }
    Ok(())
}

impl Spec {
    /// Rules the database can't check before the first write: duplicates
    /// (an apply would otherwise fight itself), one principal per
    /// assignment, `*_env` names and settings that only make sense
    /// together.
    fn check(&self) -> anyhow::Result<()> {
        unique(&self.users, |u| u.email.trim().to_lowercase(), "user")?;
        for user in &self.users {
            let what = format!("user `{}`", user.email.trim());
            match &user.password_env {
                Some(var) => check_env_name(var, &what)?,
                None if user.must_change_password.is_some() => {
                    bail!("{what}: `must_change_password` needs `password_env`")
                }
                None => {}
            }
        }
        for idp in &self.identity_providers {
            if let Some(var) = &idp.client_secret_env {
                check_env_name(var, &format!("identity provider `{}`", idp.name))?;
            }
        }
        unique(
            &self.groups,
            |g| g.display_name.trim().to_lowercase(),
            "group",
        )?;
        unique(
            &self.identity_providers,
            |i| i.name.clone(),
            "identity provider",
        )?;
        unique(&self.applications, |a| a.client_id.clone(), "application")?;
        for app in &self.applications {
            let id = &app.client_id;
            unique(
                &app.scopes,
                |s| s.value.clone(),
                &format!("scope of `{id}`"),
            )?;
            unique(&app.roles, |r| r.value.clone(), &format!("role of `{id}`"))?;
            unique(
                &app.required_permissions,
                |p| format!("{} {} {}", p.resource, p.kind, p.value),
                &format!("required permission of `{id}`"),
            )?;
        }
        for group in &self.groups {
            unique(
                &group.members,
                |m| m.trim().to_lowercase(),
                &format!("member of `{}`", group.display_name),
            )?;
        }
        unique(
            &self.directory_roles,
            |d| format!("{} {}", d.user.trim().to_lowercase(), d.role),
            "directory role",
        )?;
        for a in &self.role_assignments {
            let set = [&a.user, &a.group, &a.application]
                .iter()
                .filter(|p| p.is_some())
                .count();
            if set != 1 {
                bail!(
                    "role assignment of `{}` on `{}` needs exactly one of user, group, application",
                    a.role,
                    a.resource
                );
            }
        }
        unique(
            &self.admin_consents,
            |c| format!("{} -> {}", c.client, c.resource),
            "admin consent",
        )?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "spec_tests.rs"]
mod tests;
