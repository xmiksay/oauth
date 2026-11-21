//! Rules across the fields of an identity provider, per `kind` (pure), and
//! each kind's defaults for a new one. Checked on the row as it will be
//! stored, after a create or update applied its fields.

use entity::{
    enums::{IdpClientAuth, IdpKind},
    identity_providers,
};
use sea_orm::ActiveValue;

use crate::{
    error::AppError,
    federation::{github, kinds},
};

fn bad(msg: &str) -> AppError {
    AppError::BadRequest(msg.into())
}

/// The issuer a new IdP of `kind` gets when the body names none.
pub fn default_issuer(kind: IdpKind) -> Option<&'static str> {
    match kind {
        IdpKind::Google => Some(kinds::GOOGLE_ISSUER),
        IdpKind::Github => Some(github::GITHUB_WEB),
        IdpKind::Oidc | IdpKind::Entra => None,
    }
}

/// The scopes a new IdP of `kind` gets when the body names none.
pub fn default_scopes(kind: IdpKind) -> Vec<String> {
    let scopes: &[&str] = match kind {
        IdpKind::Github => &["read:user", "user:email"],
        _ => &["openid", "email", "profile"],
    };
    scopes.iter().map(|s| (*s).to_owned()).collect()
}

/// The fields the rules look at, as they will be stored.
pub struct Row<'a> {
    pub kind: IdpKind,
    pub issuer: &'a str,
    pub discovery_url: Option<&'a str>,
    pub scopes: &'a [String],
    pub client_auth: IdpClientAuth,
    pub hosted_domain: Option<&'a str>,
    pub allowed_tenants: &'a [String],
    pub trust_upstream_mfa: bool,
    pub trust_upstream_email: bool,
}

impl<'a> Row<'a> {
    /// `None` when a field isn't loaded (never for a create or an update).
    pub fn of(row: &'a identity_providers::ActiveModel) -> Option<Self> {
        fn v<T: Into<sea_orm::Value>>(slot: &ActiveValue<T>) -> Option<&T> {
            slot.try_as_ref()
        }
        Some(Self {
            kind: *v(&row.kind)?,
            issuer: v(&row.issuer)?,
            discovery_url: v(&row.discovery_url)?.as_deref(),
            scopes: v(&row.scopes)?,
            client_auth: *v(&row.client_auth)?,
            hosted_domain: v(&row.hosted_domain)?.as_deref(),
            allowed_tenants: v(&row.allowed_tenants)?,
            trust_upstream_mfa: *v(&row.trust_upstream_mfa)?,
            trust_upstream_email: *v(&row.trust_upstream_email)?,
        })
    }
}

/// A `{tenantid}` issuer: once, in the path (never the host), Entra only,
/// with a discovery URL (the default one would contain the placeholder).
fn check_template(row: &Row<'_>) -> Result<bool, AppError> {
    let Some((prefix, suffix)) = kinds::template(row.issuer) else {
        return Ok(false);
    };
    if row.kind != IdpKind::Entra {
        return Err(bad("only an entra issuer may contain `{tenantid}`"));
    }
    let in_path = prefix
        .split_once("://")
        .is_some_and(|(_, rest)| rest.contains('/'));
    if !in_path || suffix.contains(kinds::TENANT_PLACEHOLDER) {
        return Err(bad("`{tenantid}` may appear once, in the issuer's path"));
    }
    if row.discovery_url.is_none() {
        return Err(bad(
            "an issuer with `{tenantid}` needs a discovery_url (e.g. …/organizations/v2.0/.well-known/openid-configuration)",
        ));
    }
    Ok(true)
}

/// GitHub's endpoints are paths under the issuer (`github::metadata`), so
/// it must be a bare web origin (one trailing `/` at most: an `https` URL's
/// path is `/` for both `https://h` and `https://h/`).
fn is_origin(issuer: &str) -> bool {
    url::Url::parse(issuer).is_ok_and(|u| {
        u.path() == "/"
            && u.query().is_none()
            && u.fragment().is_none()
            && u.username().is_empty()
            && u.password().is_none()
    })
}

/// GitHub's token endpoint always wants `client_secret`: an enabled GitHub
/// provider without one could only fail every sign-in. Checked on the row
/// as stored, after the secret was sealed (or dropped by a repoint).
pub fn check_secret(row: &identity_providers::ActiveModel) -> Result<(), AppError> {
    let github = row.kind.try_as_ref() == Some(&IdpKind::Github);
    let enabled = row.enabled.try_as_ref().copied().unwrap_or(true);
    let no_secret = matches!(row.client_secret_sealed.try_as_ref(), Some(None));
    if github && enabled && no_secret {
        return Err(bad(
            "an enabled github provider needs a client_secret (GitHub requires one)",
        ));
    }
    Ok(())
}

pub fn check(row: &Row<'_>) -> Result<(), AppError> {
    let templated = check_template(row)?;
    if row
        .discovery_url
        .is_some_and(|u| u.contains(kinds::TENANT_PLACEHOLDER))
    {
        return Err(bad("discovery_url can't contain `{tenantid}`"));
    }
    if row.hosted_domain.is_some() && row.kind != IdpKind::Google {
        return Err(bad("hosted_domain is for google providers only"));
    }
    if !row.allowed_tenants.is_empty() && !templated {
        return Err(bad(
            "allowed_tenants needs an entra issuer with `{tenantid}` (multi-tenant)",
        ));
    }
    // Anyone can create an Entra tenant and put any address in a user's
    // unverified `email`: trusting it is only sound for named tenants.
    if templated && row.trust_upstream_email && row.allowed_tenants.is_empty() {
        return Err(bad(
            "trust_upstream_email on a multi-tenant entra provider needs allowed_tenants",
        ));
    }
    if row.kind == IdpKind::Github {
        if !is_origin(row.issuer) {
            return Err(bad("github issuer must be a web origin"));
        }
        if row.discovery_url.is_some() {
            return Err(bad("github providers have no discovery_url"));
        }
        if row.client_auth != IdpClientAuth::Post {
            return Err(bad("github providers use client_auth `post`"));
        }
        // GitHub reports neither MFA nor unverified addresses we'd use.
        if row.trust_upstream_mfa || row.trust_upstream_email {
            return Err(bad(
                "github providers can't trust upstream MFA or email (only a verified primary email is used)",
            ));
        }
    } else if !row.scopes.iter().any(|s| s == "openid") {
        return Err(bad("scopes must include `openid`"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULTI: &str = "https://login.example/{tenantid}/v2.0";
    const DISCOVERY: &str =
        "https://login.example/organizations/v2.0/.well-known/openid-configuration";

    fn row(kind: IdpKind, issuer: &'static str) -> Row<'static> {
        static OIDC: [String; 0] = [];
        Row {
            kind,
            issuer,
            discovery_url: None,
            scopes: &[],
            client_auth: IdpClientAuth::Post,
            hosted_domain: None,
            allowed_tenants: &OIDC,
            trust_upstream_mfa: false,
            trust_upstream_email: false,
        }
    }

    fn err(row: &Row<'_>) -> String {
        match check(row) {
            Err(AppError::BadRequest(msg)) => msg,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn openid_is_required_except_for_github() {
        let scopes = default_scopes(IdpKind::Oidc);
        let mut oidc = row(IdpKind::Oidc, "https://up.example");
        assert!(err(&oidc).contains("openid"));
        oidc.scopes = &scopes;
        assert!(check(&oidc).is_ok());
        let github_scopes = default_scopes(IdpKind::Github);
        let mut github = row(IdpKind::Github, "https://github.com");
        github.scopes = &github_scopes;
        assert!(check(&github).is_ok());
    }

    #[test]
    fn templates_are_entra_only_and_need_discovery() {
        let scopes = default_scopes(IdpKind::Entra);
        let mut entra = row(IdpKind::Entra, MULTI);
        entra.scopes = &scopes;
        assert!(err(&entra).contains("discovery_url"));
        entra.discovery_url = Some(DISCOVERY);
        assert!(check(&entra).is_ok());
        let tenants = ["9188040d-6c67-4c5b-b112-36a304b66dad".to_owned()];
        entra.allowed_tenants = &tenants;
        assert!(check(&entra).is_ok());
        let mut oidc = Row {
            kind: IdpKind::Oidc,
            allowed_tenants: &[],
            ..entra
        };
        assert!(err(&oidc).contains("only an entra"));
        oidc.issuer = "https://up.example";
        oidc.allowed_tenants = &tenants;
        assert!(err(&oidc).contains("allowed_tenants"));
        for issuer in [
            "https://{tenantid}.login.example/v2.0",
            "https://login.example/{tenantid}/{tenantid}",
        ] {
            let bad = Row { issuer, ..entra };
            assert!(err(&bad).contains("once"), "{issuer}");
        }
        let single = Row {
            issuer: "https://login.example/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
            allowed_tenants: &tenants,
            ..entra
        };
        assert!(err(&single).contains("allowed_tenants"));
        let bad_discovery = Row {
            discovery_url: Some("https://login.example/{tenantid}/x"),
            ..entra
        };
        assert!(err(&bad_discovery).contains("discovery_url"));
    }

    #[test]
    fn trusting_multi_tenant_email_needs_allowed_tenants() {
        let scopes = default_scopes(IdpKind::Entra);
        let mut entra = row(IdpKind::Entra, MULTI);
        entra.scopes = &scopes;
        entra.discovery_url = Some(DISCOVERY);
        entra.trust_upstream_email = true;
        assert!(err(&entra).contains("needs allowed_tenants"));
        let tenants = ["9188040d-6c67-4c5b-b112-36a304b66dad".to_owned()];
        entra.allowed_tenants = &tenants;
        assert!(check(&entra).is_ok());
        let single = Row {
            issuer: "https://login.example/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
            allowed_tenants: &[],
            ..entra
        };
        assert!(check(&single).is_ok());
    }

    #[test]
    fn kind_specific_fields() {
        let scopes = default_scopes(IdpKind::Google);
        let mut google = row(IdpKind::Google, "https://accounts.google.com");
        google.scopes = &scopes;
        google.hosted_domain = Some("contoso.com");
        assert!(check(&google).is_ok());
        google.kind = IdpKind::Oidc;
        assert!(err(&google).contains("hosted_domain"));
        let mut github = row(IdpKind::Github, "https://github.com");
        github.trust_upstream_email = true;
        assert!(err(&github).contains("github"));
        github.trust_upstream_email = false;
        github.client_auth = IdpClientAuth::Basic;
        assert!(err(&github).contains("post"));
        github.client_auth = IdpClientAuth::Post;
        github.discovery_url = Some("https://github.com/x");
        assert!(err(&github).contains("discovery_url"));
    }

    #[test]
    fn github_issuer_is_a_web_origin() {
        for ok in [
            "https://github.com",
            "https://github.com/",
            "https://ghe.example:8443",
        ] {
            assert!(check(&row(IdpKind::Github, ok)).is_ok(), "{ok}");
        }
        for issuer in [
            "https://github.com/foo",
            "https://github.com/foo/",
            "https://github.com//",
            "https://github.com/?x=1",
            "https://github.com/#x",
            "https://u@github.com",
        ] {
            assert!(
                err(&row(IdpKind::Github, issuer)).contains("web origin"),
                "{issuer}"
            );
        }
    }

    #[test]
    fn enabled_github_needs_a_secret() {
        use sea_orm::Set;
        let mut row = identity_providers::ActiveModel {
            kind: Set(IdpKind::Github),
            enabled: Set(true),
            client_secret_sealed: Set(None),
            ..Default::default()
        };
        assert!(
            matches!(check_secret(&row), Err(AppError::BadRequest(m)) if m.contains("client_secret"))
        );
        row.enabled = Set(false);
        assert!(check_secret(&row).is_ok());
        row.enabled = Set(true);
        row.client_secret_sealed = Set(Some(vec![1]));
        assert!(check_secret(&row).is_ok());
        row.kind = Set(IdpKind::Oidc);
        row.client_secret_sealed = Set(None);
        assert!(check_secret(&row).is_ok());
    }
}
