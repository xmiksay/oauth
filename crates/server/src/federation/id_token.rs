//! Verifying an upstream ID token: the signature with a key from the
//! provider's JWKS (algorithm dictated by the key, never by the token), then
//! the claims (OIDC Core §3.1.3.7).

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, PublicKeyUse},
};
use serde_json::{Map, Value};

use super::{Failure, Upstream, discovery::Metadata, profile};
use crate::secret;

/// Allowed clock difference to the provider, both ways.
pub const SKEW_SECS: i64 = 60;
const MAX_SUBJECT_LEN: usize = 255;
const MAX_AMR_VALUES: usize = 20;

/// What the token must match.
pub struct Expected<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    /// Unix seconds.
    pub now: i64,
    /// Re-authentication was demanded (`prompt=login`, `max_age`): the
    /// token's `auth_time` must be present and no earlier than this (unix
    /// seconds, minus the skew).
    pub min_auth_time: Option<i64>,
}

/// The claims we use from a verified token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    /// The upstream `auth_time`, never later than now.
    pub auth_time: Option<i64>,
}

fn str_claim<'a>(claims: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    claims.get(name).and_then(Value::as_str)
}

fn audience_ok(claims: &Map<String, Value>, client_id: &str) -> bool {
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(aud)) => vec![aud.as_str()],
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).collect(),
        _ => return false,
    };
    if !audiences.contains(&client_id) {
        return false;
    }
    // §3.1.3.7 items 4-5: with other audiences the token must have been
    // issued to us (`azp`); an `azp` naming anyone else is refused anyway.
    match str_claim(claims, "azp") {
        Some(azp) => azp == client_id,
        None => audiences.len() == 1,
    }
}

/// Checks `claims` of a token whose signature was verified.
pub fn check_claims(
    claims: &Map<String, Value>,
    expected: &Expected<'_>,
) -> Result<Claims, Failure> {
    if str_claim(claims, "iss") != Some(expected.issuer) {
        return Err(Failure("id_token_iss"));
    }
    if !audience_ok(claims, expected.client_id) {
        return Err(Failure("id_token_aud"));
    }
    let exp = claims.get("exp").and_then(Value::as_i64);
    if !exp.is_some_and(|exp| exp.saturating_add(SKEW_SECS) > expected.now) {
        return Err(Failure("id_token_expired"));
    }
    let iat = claims.get("iat").and_then(Value::as_i64);
    if !iat.is_some_and(|iat| iat <= expected.now.saturating_add(SKEW_SECS)) {
        return Err(Failure("id_token_iat"));
    }
    let nbf = claims.get("nbf");
    if nbf.is_some_and(|nbf| {
        !nbf.as_i64()
            .is_some_and(|nbf| nbf <= expected.now.saturating_add(SKEW_SECS))
    }) {
        return Err(Failure("id_token_nbf"));
    }
    let auth_time = claims
        .get("auth_time")
        .and_then(Value::as_i64)
        .map(|t| t.min(expected.now));
    if let Some(min) = expected.min_auth_time
        && !auth_time.is_some_and(|t| t.saturating_add(SKEW_SECS) >= min)
    {
        return Err(Failure("id_token_auth_time"));
    }
    let nonce_ok = str_claim(claims, "nonce")
        .is_some_and(|n| secret::ct_eq(n.as_bytes(), expected.nonce.as_bytes()));
    if !nonce_ok {
        return Err(Failure("id_token_nonce"));
    }
    let subject = str_claim(claims, "sub")
        .filter(|s| !s.is_empty() && s.len() <= MAX_SUBJECT_LEN)
        .filter(|s| !s.chars().any(char::is_control))
        .ok_or(Failure("id_token_sub"))?;
    let email_verified = match claims.get("email_verified") {
        Some(Value::Bool(v)) => *v,
        // Some providers send the boolean as a string.
        Some(Value::String(v)) => v == "true",
        _ => false,
    };
    let name = str_claim(claims, "name")
        .and_then(profile::clean_name)
        .or_else(|| {
            let parts: Vec<String> = ["given_name", "family_name"]
                .iter()
                .filter_map(|c| str_claim(claims, c).and_then(profile::clean_name))
                .collect();
            profile::clean_name(&parts.join(" "))
        });
    let amr = match claims.get("amr") {
        Some(Value::Array(list)) => list
            .iter()
            .filter_map(Value::as_str)
            .take(MAX_AMR_VALUES)
            .filter_map(profile::clean_token)
            .collect(),
        _ => Vec::new(),
    };
    Ok(Claims {
        subject: subject.to_owned(),
        email: str_claim(claims, "email").and_then(profile::clean_email),
        email_verified,
        name,
        amr,
        acr: str_claim(claims, "acr").and_then(profile::clean_token),
        auth_time,
    })
}

/// The one algorithm a key may verify: RS256 for RSA, ES256 for P-256,
/// EdDSA for Ed25519. A key announcing another `alg`, or meant for
/// encryption, verifies nothing.
pub fn key_algorithm(jwk: &Jwk) -> Option<Algorithm> {
    let (alg, announced) = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => (Algorithm::RS256, KeyAlgorithm::RS256),
        AlgorithmParameters::EllipticCurve(p) if p.curve == EllipticCurve::P256 => {
            (Algorithm::ES256, KeyAlgorithm::ES256)
        }
        AlgorithmParameters::OctetKeyPair(p) if p.curve == EllipticCurve::Ed25519 => {
            (Algorithm::EdDSA, KeyAlgorithm::EdDSA)
        }
        _ => return None,
    };
    let alg_ok = jwk.common.key_algorithm.is_none_or(|a| a == announced);
    let use_ok = jwk
        .common
        .public_key_use
        .as_ref()
        .is_none_or(|u| *u == PublicKeyUse::Signature);
    (alg_ok && use_ok).then_some(alg)
}

impl Upstream {
    /// Verifies `token` against the provider's JWKS and `expected`.
    pub async fn verify_id_token(
        &self,
        meta: &Metadata,
        token: &str,
        expected: &Expected<'_>,
    ) -> Result<Claims, Failure> {
        let header =
            jsonwebtoken::decode_header(token).map_err(|_| Failure("id_token_malformed"))?;
        if !matches!(
            header.alg,
            Algorithm::RS256 | Algorithm::ES256 | Algorithm::EdDSA
        ) {
            return Err(Failure("id_token_alg"));
        }
        let jwk = self
            .signing_key(&meta.jwks_uri, header.kid.as_deref())
            .await?;
        let alg = key_algorithm(&jwk).ok_or(Failure("jwk_unusable"))?;
        if header.alg != alg {
            return Err(Failure("id_token_alg"));
        }
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| Failure("jwk_unusable"))?;
        let mut validation = Validation::new(alg);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.set_required_spec_claims::<&str>(&[]);
        let claims = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|_| Failure("id_token_signature"))?
            .claims;
        check_claims(&claims, expected)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn expected() -> Expected<'static> {
        Expected {
            issuer: "https://up.example",
            client_id: "rp",
            nonce: "n-123",
            now: NOW,
            min_auth_time: None,
        }
    }

    fn good() -> Map<String, Value> {
        json!({
            "iss": "https://up.example", "aud": "rp", "sub": "u-1",
            "exp": NOW + 300, "iat": NOW, "nonce": "n-123",
            "email": "a@b.example", "email_verified": true,
            "given_name": "Ann", "family_name": "Lee", "amr": ["pwd", "mfa"], "acr": "x",
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn with(changes: Value) -> Map<String, Value> {
        let mut claims = good();
        for (k, v) in changes.as_object().unwrap() {
            if v.is_null() {
                claims.remove(k);
            } else {
                claims.insert(k.clone(), v.clone());
            }
        }
        claims
    }

    fn reason(claims: &Map<String, Value>) -> &'static str {
        check_claims(claims, &expected()).unwrap_err().0
    }

    #[test]
    fn good_token_yields_claims() {
        let c = check_claims(&good(), &expected()).unwrap();
        assert_eq!(c.subject, "u-1");
        assert_eq!(c.name.as_deref(), Some("Ann Lee"));
        assert!(c.email_verified);
        assert_eq!(c.amr, ["pwd", "mfa"]);
        assert_eq!(c.acr.as_deref(), Some("x"));
        let c = check_claims(&with(json!({"name": " Ann L "})), &expected()).unwrap();
        assert_eq!(c.name.as_deref(), Some("Ann L"));
        let c = check_claims(&with(json!({"email_verified": "true"})), &expected()).unwrap();
        assert!(c.email_verified);
        let c = check_claims(&with(json!({"email_verified": null})), &expected()).unwrap();
        assert!(!c.email_verified);
    }

    #[test]
    fn issuer_must_match_exactly() {
        assert_eq!(
            reason(&with(json!({"iss": "https://up.example/"}))),
            "id_token_iss"
        );
        assert_eq!(reason(&with(json!({"iss": null}))), "id_token_iss");
    }

    #[test]
    fn audience_and_azp() {
        assert_eq!(reason(&with(json!({"aud": "other"}))), "id_token_aud");
        assert_eq!(reason(&with(json!({"aud": null}))), "id_token_aud");
        assert!(check_claims(&with(json!({"aud": ["rp"]})), &expected()).is_ok());
        assert_eq!(reason(&with(json!({"aud": ["rp", "x"]}))), "id_token_aud");
        let ok = with(json!({"aud": ["rp", "x"], "azp": "rp"}));
        assert!(check_claims(&ok, &expected()).is_ok());
        assert_eq!(reason(&with(json!({"azp": "x"}))), "id_token_aud");
    }

    #[test]
    fn times_allow_one_minute_of_skew() {
        assert!(check_claims(&with(json!({"exp": NOW - 59})), &expected()).is_ok());
        assert_eq!(reason(&with(json!({"exp": NOW - 60}))), "id_token_expired");
        assert_eq!(reason(&with(json!({"exp": null}))), "id_token_expired");
        assert!(check_claims(&with(json!({"iat": NOW + 60})), &expected()).is_ok());
        assert_eq!(reason(&with(json!({"iat": NOW + 61}))), "id_token_iat");
        assert_eq!(reason(&with(json!({"iat": null}))), "id_token_iat");
    }

    #[test]
    fn nbf_and_auth_time() {
        assert!(check_claims(&with(json!({"nbf": NOW + 60})), &expected()).is_ok());
        assert_eq!(reason(&with(json!({"nbf": NOW + 61}))), "id_token_nbf");
        assert_eq!(reason(&with(json!({"nbf": "soon"}))), "id_token_nbf");
        let reauth = Expected {
            min_auth_time: Some(NOW - 100),
            ..expected()
        };
        let at = |t: Value| check_claims(&with(json!({ "auth_time": t })), &reauth);
        assert_eq!(at(json!(NOW - 100)).unwrap().auth_time, Some(NOW - 100));
        assert!(at(json!(NOW - 160)).is_ok());
        assert_eq!(at(json!(NOW - 161)).unwrap_err().0, "id_token_auth_time");
        assert_eq!(at(Value::Null).unwrap_err().0, "id_token_auth_time");
        // A future auth_time is clamped to now.
        let c = check_claims(&with(json!({ "auth_time": NOW + 999 })), &expected()).unwrap();
        assert_eq!(c.auth_time, Some(NOW));
    }

    #[test]
    fn profile_claims_are_bounded() {
        let c = check_claims(
            &with(json!({ "name": "A\u{0}B", "email": "a\u{0}@b", "acr": "x".repeat(300) })),
            &expected(),
        )
        .unwrap();
        assert_eq!(c.name.as_deref(), Some("AB"));
        assert_eq!((c.email, c.acr), (None, None));
        let c = check_claims(&with(json!({ "name": "é".repeat(300) })), &expected()).unwrap();
        assert_eq!(c.name.unwrap().chars().count(), 256);
    }

    #[test]
    fn nonce_and_subject() {
        assert_eq!(reason(&with(json!({"nonce": "n-124"}))), "id_token_nonce");
        assert_eq!(reason(&with(json!({"nonce": null}))), "id_token_nonce");
        assert_eq!(reason(&with(json!({"sub": ""}))), "id_token_sub");
        assert_eq!(reason(&with(json!({"sub": "a\nb"}))), "id_token_sub");
        assert_eq!(
            reason(&with(json!({"sub": "x".repeat(256)}))),
            "id_token_sub"
        );
    }

    #[test]
    fn key_dictates_the_algorithm() {
        let jwk = |v: Value| -> Jwk { serde_json::from_value(v).unwrap() };
        let ed = json!({ "kty": "OKP", "crv": "Ed25519", "x": "AAAA" });
        assert_eq!(key_algorithm(&jwk(ed.clone())), Some(Algorithm::EdDSA));
        let mut ed_hs = ed.clone();
        ed_hs["alg"] = "HS256".into();
        assert_eq!(key_algorithm(&jwk(ed_hs)), None);
        let mut ed_enc = ed;
        ed_enc["use"] = "enc".into();
        assert_eq!(key_algorithm(&jwk(ed_enc)), None);
        let oct = json!({ "kty": "oct", "k": "c2VjcmV0" });
        assert_eq!(key_algorithm(&jwk(oct)), None);
        let p384 = json!({ "kty": "EC", "crv": "P-384", "x": "AA", "y": "AA" });
        assert_eq!(key_algorithm(&jwk(p384)), None);
        let rsa = json!({ "kty": "RSA", "n": "AQAB", "e": "AQAB", "alg": "RS256" });
        assert_eq!(key_algorithm(&jwk(rsa)), Some(Algorithm::RS256));
    }
}
