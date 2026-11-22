//! GitHub as an upstream provider: OAuth 2.0 without OpenID. The endpoints
//! derive from the configured `issuer` (the web origin, `https://github.com`
//! or a GitHub Enterprise Server); the identity comes from the REST API —
//! `GET /user` (numeric `id` = subject, `name` / `login`) and
//! `GET /user/emails` (only the verified primary address is used). The
//! access token is used for those two calls and dropped.

use entity::identity_providers;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{
    Failure, Upstream, discovery::Metadata, exchange::Exchange, group_map, id_token::Claims,
    profile, urls,
};

/// github.com's web origin (the preset's default issuer).
pub const GITHUB_WEB: &str = "https://github.com";
const GITHUB_API: &str = "https://api.github.com";
const ACCEPT: &str = "application/vnd.github+json";
/// Addresses looked at (GitHub caps an account's emails far below this).
const MAX_EMAILS: usize = 100;

fn base(issuer: &str) -> &str {
    issuer.trim_end_matches('/')
}

/// The REST API root: `api.github.com` for github.com, `{issuer}/api/v3`
/// for GitHub Enterprise Server.
pub fn api_base(issuer: &str) -> String {
    if base(issuer) == GITHUB_WEB {
        GITHUB_API.to_owned()
    } else {
        format!("{}/api/v3", base(issuer))
    }
}

/// The endpoints of a GitHub IdP (no discovery): `Ok(None)` for other
/// kinds, a [`Failure`] if they fail the URL policy.
pub fn metadata(
    idp: &identity_providers::Model,
    allow_http_loopback: bool,
) -> Result<Option<Metadata>, Failure> {
    if idp.kind != entity::enums::IdpKind::Github {
        return Ok(None);
    }
    let web = base(&idp.issuer);
    let meta = Metadata {
        issuer: idp.issuer.clone(),
        authorization_endpoint: format!("{web}/login/oauth/authorize"),
        token_endpoint: format!("{web}/login/oauth/access_token"),
        jwks_uri: String::new(),
    };
    for endpoint in [&meta.authorization_endpoint, &meta.token_endpoint] {
        if urls::checked(endpoint, allow_http_loopback).is_none() {
            return Err(Failure("discovery_endpoint_refused"));
        }
    }
    Ok(Some(meta))
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
}

#[derive(Deserialize)]
struct User {
    id: u64,
    login: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct Email {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

/// The verified primary address, if there is one.
fn primary_verified(emails: &[Email]) -> Option<String> {
    emails
        .iter()
        .take(MAX_EMAILS)
        .find(|e| e.primary && e.verified)
        .and_then(|e| profile::clean_email(&e.email))
}

fn claims(user: User, emails: &[Email]) -> Claims {
    let email = primary_verified(emails);
    Claims {
        subject: user.id.to_string(),
        email_verified: email.is_some(),
        email,
        name: user
            .name
            .as_deref()
            .and_then(profile::clean_name)
            .or_else(|| user.login.as_deref().and_then(profile::clean_name)),
        amr: Vec::new(),
        acr: None,
        auth_time: None,
        // No ID token, no claims: group mappings stay undecided.
        mapped: group_map::Mapped::default(),
    }
}

impl Upstream {
    /// Redeems the code at GitHub and reads the account behind it.
    pub async fn github_identity(
        &self,
        idp: &identity_providers::Model,
        meta: &Metadata,
        ex: Exchange<'_>,
    ) -> Result<Claims, Failure> {
        let raw = self.redeem(meta, ex).await?;
        // GitHub answers a bad code with 200 and an `error` body.
        let parsed: TokenResponse =
            serde_json::from_slice(&raw).map_err(|_| Failure("token_response"))?;
        let token = Zeroizing::new(parsed.access_token.ok_or(Failure("token_refused"))?);
        let api = api_base(&idp.issuer);
        let user: User = self
            .get_json_as(&format!("{api}/user"), "github_user", Some(&token), ACCEPT)
            .await?;
        // Without the `user:email` scope GitHub answers 403 / 404: no
        // email then. Anything else (outage, bad body) is a failure, not an
        // account without one.
        let emails: Vec<Email> = self
            .get_json_unless(
                &format!("{api}/user/emails"),
                "github_emails",
                Some(&token),
                ACCEPT,
                &[
                    reqwest::StatusCode::FORBIDDEN,
                    reqwest::StatusCode::NOT_FOUND,
                ],
            )
            .await?
            .unwrap_or_default();
        Ok(claims(user, &emails))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn emails(v: serde_json::Value) -> Vec<Email> {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn api_base_follows_the_issuer() {
        assert_eq!(api_base("https://github.com"), "https://api.github.com");
        assert_eq!(api_base("https://github.com/"), "https://api.github.com");
        assert_eq!(
            api_base("https://ghe.example"),
            "https://ghe.example/api/v3"
        );
    }

    #[test]
    fn only_the_verified_primary_email_counts() {
        let list = emails(json!([
            { "email": "a@x.example", "primary": false, "verified": true },
            { "email": "b@x.example", "primary": true, "verified": true },
        ]));
        assert_eq!(primary_verified(&list).as_deref(), Some("b@x.example"));
        let unverified = emails(json!([
            { "email": "a@x.example", "primary": false, "verified": true },
            { "email": "b@x.example", "primary": true, "verified": false },
        ]));
        assert_eq!(primary_verified(&unverified), None);
        assert_eq!(primary_verified(&emails(json!([{ "email": "c@x" }]))), None);
    }

    #[test]
    fn claims_use_the_numeric_id() {
        let user: User =
            serde_json::from_value(json!({ "id": 583231, "login": "octocat", "name": null }))
                .unwrap();
        let list = emails(json!([{ "email": "o@x.example", "primary": true, "verified": true }]));
        let c = claims(user, &list);
        assert_eq!(c.subject, "583231");
        assert_eq!(c.name.as_deref(), Some("octocat"));
        assert!(c.email_verified);
        assert_eq!(c.email.as_deref(), Some("o@x.example"));
        let user: User =
            serde_json::from_value(json!({ "id": 1, "login": "x", "name": " Mona " })).unwrap();
        let c = claims(user, &[]);
        assert_eq!(
            (c.name.as_deref(), c.email, c.email_verified),
            (Some("Mona"), None, false)
        );
        assert!(serde_json::from_value::<User>(json!({ "id": "1" })).is_err());
    }
}
