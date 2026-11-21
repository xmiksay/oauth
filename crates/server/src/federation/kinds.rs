//! What a provider's `kind` adds to plain OpenID (pure): Google's hosted
//! domain, Entra's tenant (`tid`) and `{tenantid}`-templated multi-tenant
//! issuer, Entra's `xms_edov` email verification, and the per-IdP
//! `trust_upstream_email` override. GitHub isn't OpenID: `github`.

use entity::{enums::IdpKind, identity_providers};
use serde_json::{Map, Value};

use super::{Failure, id_token::Claims};

/// Stands for the signing tenant in a multi-tenant Entra issuer, as
/// Microsoft's `organizations` / `common` discovery documents write it.
pub const TENANT_PLACEHOLDER: &str = "{tenantid}";
const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// The kind-specific settings of one provider.
#[derive(Clone, Copy, Debug)]
pub struct Rules<'a> {
    pub kind: IdpKind,
    /// As configured (an Entra one may contain [`TENANT_PLACEHOLDER`]).
    pub issuer: &'a str,
    pub hosted_domain: Option<&'a str>,
    pub allowed_tenants: &'a [String],
    pub trust_upstream_email: bool,
}

impl<'a> Rules<'a> {
    pub fn of(idp: &'a identity_providers::Model) -> Self {
        Self {
            kind: idp.kind,
            issuer: &idp.issuer,
            hosted_domain: idp.hosted_domain.as_deref(),
            allowed_tenants: &idp.allowed_tenants,
            trust_upstream_email: idp.trust_upstream_email,
        }
    }

    /// Plain OpenID rules for `issuer`.
    pub fn oidc(issuer: &'a str) -> Self {
        Self {
            kind: IdpKind::Oidc,
            issuer,
            hosted_domain: None,
            allowed_tenants: &[],
            trust_upstream_email: false,
        }
    }
}

/// An Entra directory (tenant) id: a GUID, lower-case as Entra writes it.
pub fn is_tenant_id(raw: &str) -> bool {
    let groups: Vec<&str> = raw.split('-').collect();
    groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups.iter().all(|g| {
            g.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// `(prefix, suffix)` around the placeholder of a templated issuer.
pub fn template(issuer: &str) -> Option<(&str, &str)> {
    issuer.split_once(TENANT_PLACEHOLDER)
}

/// The tenant id `iss` fills a templated `issuer` with, if it matches.
fn templated_tenant<'i>(issuer: &str, iss: &'i str) -> Option<&'i str> {
    let (prefix, suffix) = template(issuer)?;
    let tid = iss.strip_prefix(prefix)?.strip_suffix(suffix)?;
    is_tenant_id(tid).then_some(tid)
}

/// Whether `iss` (an ID token's, or the callback's RFC 9207 parameter) is
/// the configured issuer: exactly; for Entra with a templated issuer, the
/// template with a tenant id filled in; for Google also the scheme-less
/// form Google documents it may use.
pub fn issuer_matches(rules: &Rules<'_>, iss: &str) -> bool {
    match rules.kind {
        IdpKind::Entra if template(rules.issuer).is_some() => {
            templated_tenant(rules.issuer, iss).is_some()
        }
        IdpKind::Google if rules.issuer == GOOGLE_ISSUER => {
            iss == GOOGLE_ISSUER || iss == "accounts.google.com"
        }
        _ => iss == rules.issuer,
    }
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(v)) => *v,
        Some(Value::String(v)) => v == "true" || v == "1",
        Some(Value::Number(n)) => n.as_i64() == Some(1),
        _ => false,
    }
}

/// The kind's checks on the signature-verified `raw` claims, after the
/// generic ones produced `claims` (whose `email_verified` they may raise).
pub fn check(
    rules: &Rules<'_>,
    raw: &Map<String, Value>,
    claims: &mut Claims,
) -> Result<(), Failure> {
    let str_claim = |name: &str| raw.get(name).and_then(Value::as_str);
    match rules.kind {
        IdpKind::Google => {
            if let Some(want) = rules.hosted_domain
                && !str_claim("hd").is_some_and(|hd| hd.eq_ignore_ascii_case(want))
            {
                return Err(Failure("id_token_hd"));
            }
        }
        IdpKind::Entra => {
            let tid = str_claim("tid")
                .filter(|t| is_tenant_id(t))
                .ok_or(Failure("id_token_tid"))?;
            // The issuer must name the tenant the token says it is from:
            // a token of tenant A can't claim tenant B's `tid`.
            if template(rules.issuer).is_some()
                && str_claim("iss").and_then(|iss| templated_tenant(rules.issuer, iss)) != Some(tid)
            {
                return Err(Failure("id_token_tid"));
            }
            if !rules.allowed_tenants.is_empty() && !rules.allowed_tenants.iter().any(|t| t == tid)
            {
                return Err(Failure("tenant_not_allowed"));
            }
            // Entra doesn't send `email_verified`; `xms_edov` says the
            // email's domain is verified by the tenant that owns it.
            if truthy(raw.get("xms_edov")) {
                claims.email_verified = true;
            }
        }
        IdpKind::Oidc | IdpKind::Github => {}
    }
    if rules.trust_upstream_email {
        claims.email_verified = true;
    }
    claims.email_verified &= claims.email.is_some();
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TID: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
    const OTHER: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    const MULTI: &str = "https://login.example/{tenantid}/v2.0";

    fn rules(kind: IdpKind, issuer: &'static str) -> Rules<'static> {
        Rules {
            kind,
            ..Rules::oidc(issuer)
        }
    }

    fn claims(email: Option<&str>, verified: bool) -> Claims {
        Claims {
            subject: "s".into(),
            email: email.map(str::to_owned),
            email_verified: verified,
            name: None,
            amr: vec![],
            acr: None,
            auth_time: None,
            mapped: Default::default(),
        }
    }

    fn run(rules: &Rules<'_>, raw: Value, verified: bool) -> Result<bool, &'static str> {
        let mut c = claims(Some("a@b.example"), verified);
        let raw = raw.as_object().cloned().unwrap_or_default();
        check(rules, &raw, &mut c)
            .map(|()| c.email_verified)
            .map_err(|f| f.0)
    }

    #[test]
    fn tenant_ids_are_lowercase_guids() {
        assert!(is_tenant_id(TID));
        assert!(!is_tenant_id(&TID.to_uppercase()));
        assert!(!is_tenant_id("organizations"));
        assert!(!is_tenant_id("9188040d-6c67-4c5b-b112-36a304b66da/"));
        assert!(!is_tenant_id(&format!("{TID}-0")));
        assert!(!is_tenant_id(""));
    }

    #[test]
    fn issuers() {
        let multi = rules(IdpKind::Entra, MULTI);
        assert!(issuer_matches(
            &multi,
            &format!("https://login.example/{TID}/v2.0")
        ));
        assert!(!issuer_matches(&multi, MULTI));
        assert!(!issuer_matches(&multi, "https://login.example/evil/x/v2.0"));
        assert!(!issuer_matches(
            &multi,
            &format!("https://login.example/{TID}/v2.0/")
        ));
        // Only Entra fills the template; elsewhere it is a literal.
        let oidc = Rules::oidc(MULTI);
        assert!(!issuer_matches(
            &oidc,
            &format!("https://login.example/{TID}/v2.0")
        ));
        assert!(issuer_matches(&oidc, MULTI));
        let google = rules(IdpKind::Google, GOOGLE_ISSUER);
        assert!(issuer_matches(&google, "accounts.google.com"));
        assert!(issuer_matches(&google, GOOGLE_ISSUER));
        assert!(!issuer_matches(&google, "https://accounts.google.com/"));
        assert!(!issuer_matches(
            &Rules::oidc(GOOGLE_ISSUER),
            "accounts.google.com"
        ));
    }

    #[test]
    fn google_hosted_domain() {
        let mut google = rules(IdpKind::Google, GOOGLE_ISSUER);
        assert_eq!(run(&google, json!({}), true), Ok(true));
        google.hosted_domain = Some("contoso.com");
        assert_eq!(run(&google, json!({ "hd": "Contoso.com" }), true), Ok(true));
        assert_eq!(
            run(&google, json!({ "hd": "fabrikam.com" }), true),
            Err("id_token_hd")
        );
        assert_eq!(run(&google, json!({}), true), Err("id_token_hd"));
        // Google's own email_verified stays authoritative.
        assert_eq!(
            run(&google, json!({ "hd": "contoso.com" }), false),
            Ok(false)
        );
    }

    #[test]
    fn entra_tenant_and_issuer() {
        let iss = |tid: &str| format!("https://login.example/{tid}/v2.0");
        let multi = rules(IdpKind::Entra, MULTI);
        assert_eq!(
            run(&multi, json!({ "tid": TID, "iss": iss(TID) }), false),
            Ok(false)
        );
        assert_eq!(
            run(&multi, json!({ "tid": OTHER, "iss": iss(TID) }), false),
            Err("id_token_tid")
        );
        assert_eq!(
            run(&multi, json!({ "iss": iss(TID) }), false),
            Err("id_token_tid")
        );
        assert_eq!(
            run(&multi, json!({ "tid": "x", "iss": iss(TID) }), false),
            Err("id_token_tid")
        );
        let allowed = [OTHER.to_owned()];
        let only_other = Rules {
            allowed_tenants: &allowed,
            ..multi
        };
        assert_eq!(
            run(&only_other, json!({ "tid": TID, "iss": iss(TID) }), false),
            Err("tenant_not_allowed")
        );
        assert_eq!(
            run(
                &only_other,
                json!({ "tid": OTHER, "iss": iss(OTHER) }),
                false
            ),
            Ok(false)
        );
        let single = rules(
            IdpKind::Entra,
            "https://login.example/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
        );
        assert_eq!(run(&single, json!({ "tid": TID }), false), Ok(false));
        assert_eq!(run(&single, json!({}), false), Err("id_token_tid"));
    }

    #[test]
    fn entra_email_verification() {
        let single = rules(IdpKind::Entra, "https://login.example/t/v2.0");
        for edov in [json!(true), json!("true"), json!("1"), json!(1)] {
            assert_eq!(
                run(&single, json!({ "tid": TID, "xms_edov": edov }), false),
                Ok(true)
            );
        }
        for edov in [json!(false), json!("0"), json!(0), Value::Null] {
            assert_eq!(
                run(&single, json!({ "tid": TID, "xms_edov": edov }), false),
                Ok(false)
            );
        }
        // Without an email nothing is verified.
        let mut c = claims(None, false);
        let raw = json!({ "tid": TID, "xms_edov": true });
        check(&single, raw.as_object().unwrap(), &mut c).unwrap();
        assert!(!c.email_verified);
    }

    #[test]
    fn trust_upstream_email_overrides() {
        let mut oidc = Rules::oidc("https://up.example");
        assert_eq!(run(&oidc, json!({}), false), Ok(false));
        oidc.trust_upstream_email = true;
        assert_eq!(run(&oidc, json!({}), false), Ok(true));
        let mut c = claims(None, false);
        check(&oidc, &Map::new(), &mut c).unwrap();
        assert!(!c.email_verified);
    }
}
