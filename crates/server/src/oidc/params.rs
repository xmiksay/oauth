//! Request parameter parsing shared by the protocol endpoints, and the
//! validated authorize request persisted in a login transaction.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Decodes `application/x-www-form-urlencoded` (query string or body).
/// RFC 6749 §3.1: parameters MUST NOT be included more than once; empty
/// values are treated as omitted.
pub fn parse_unique(raw: &[u8]) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    for (key, value) in form_urlencoded::parse(raw) {
        if value.is_empty() {
            continue;
        }
        if out.insert(key.to_string(), value.into_owned()).is_some() {
            return Err(format!("parameter `{key}` repeated"));
        }
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Prompt {
    None,
    Login,
    Consent,
}

impl Prompt {
    /// OIDC allows a space-separated list; `none` must stand alone. Only
    /// one of `login` / `consent` is tracked: `login consent` behaves like
    /// `login` followed by the consent check, which is what we do anyway
    /// except that consent is then not forced.
    pub fn parse(raw: &str) -> Result<Option<Self>, String> {
        let values: Vec<&str> = raw.split_ascii_whitespace().collect();
        if values.contains(&"none") && values.len() > 1 {
            return Err("prompt=none must not be combined with other values".into());
        }
        let mut prompt = None;
        for value in values {
            let parsed = match value {
                "none" => Self::None,
                "login" => Self::Login,
                "consent" => Self::Consent,
                other => return Err(format!("unsupported prompt value `{other}`")),
            };
            // `login` wins: it is the stricter of the two.
            if prompt != Some(Self::Login) {
                prompt = Some(parsed);
            }
        }
        Ok(prompt)
    }
}

/// A fully validated authorization request (stored as JSON in
/// `login_transactions.params`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    /// Subset of `openid profile email offline_access`.
    pub oidc_scopes: Vec<String>,
    pub resource_id: Option<Uuid>,
    /// Scope values of the resource (never `.default`; already expanded).
    pub resource_scopes: Vec<String>,
    pub prompt: Option<Prompt>,
    pub max_age: Option<i64>,
    /// Home-realm discovery: an email domain whose identity provider the
    /// login page should go to directly (absent in transactions stored
    /// before federation existed, hence the defaults).
    #[serde(default)]
    pub domain_hint: Option<String>,
    /// The id of the identity provider to go to directly.
    #[serde(default)]
    pub idp: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rejects_duplicates() {
        let params = parse_unique(b"a=1&b=x+y%2Fz&empty=").unwrap();
        assert_eq!(params["a"], "1");
        assert_eq!(params["b"], "x y/z");
        assert!(!params.contains_key("empty"));
        assert!(parse_unique(b"a=1&a=2").is_err());
    }

    #[test]
    fn prompt_values() {
        assert_eq!(Prompt::parse("none").unwrap(), Some(Prompt::None));
        assert_eq!(Prompt::parse("login").unwrap(), Some(Prompt::Login));
        assert_eq!(Prompt::parse("consent").unwrap(), Some(Prompt::Consent));
        assert_eq!(Prompt::parse("consent login").unwrap(), Some(Prompt::Login));
        assert_eq!(Prompt::parse("login consent").unwrap(), Some(Prompt::Login));
        assert!(Prompt::parse("none login").is_err());
        assert!(Prompt::parse("select_account").is_err());
    }

    #[test]
    fn auth_request_roundtrips_as_json() {
        let req = AuthRequest {
            client_id: "app".into(),
            redirect_uri: "https://app/cb".into(),
            state: Some("s".into()),
            nonce: None,
            code_challenge: "c".into(),
            oidc_scopes: vec!["openid".into()],
            resource_id: Some(Uuid::nil()),
            resource_scopes: vec!["read".into()],
            prompt: Some(Prompt::Consent),
            max_age: Some(0),
            domain_hint: Some("contoso.com".into()),
            idp: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["prompt"], "consent");
        assert_eq!(
            serde_json::from_value::<AuthRequest>(json.clone()).unwrap(),
            req
        );
        // Transactions stored before the federation fields existed.
        let mut old = json;
        let fields = old.as_object_mut().unwrap();
        fields.remove("domain_hint");
        fields.remove("idp");
        let parsed = serde_json::from_value::<AuthRequest>(old).unwrap();
        assert_eq!((parsed.domain_hint, parsed.idp), (None, None));
    }
}
