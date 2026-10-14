//! `clientDataJSON` (WebAuthn §5.8.1). The challenge itself is matched by
//! the caller against its stored (hashed) challenge.

use serde::Deserialize;

use super::{MAX_CLIENT_DATA, WebauthnError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ceremony {
    Create,
    Get,
}

impl Ceremony {
    fn type_name(self) -> &'static str {
        match self {
            Self::Create => "webauthn.create",
            Self::Get => "webauthn.get",
        }
    }
}

// Derived `Deserialize` rejects duplicate fields; unknown ones are allowed
// (the spec reserves room for future members).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Raw {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    cross_origin: Option<bool>,
    top_origin: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientData {
    kind: String,
    /// base64url, as the browser encoded the challenge bytes.
    pub challenge: String,
    origin: String,
    cross_origin: bool,
}

/// Longest challenge string accepted (ours are 43 characters).
const MAX_CHALLENGE: usize = 128;

pub fn parse(json: &[u8]) -> Result<ClientData, WebauthnError> {
    const MALFORMED: WebauthnError = WebauthnError::Malformed("client data");
    if json.len() > MAX_CLIENT_DATA {
        return Err(MALFORMED);
    }
    let raw: Raw = serde_json::from_slice(json).map_err(|_| MALFORMED)?;
    if raw.challenge.is_empty() || raw.challenge.len() > MAX_CHALLENGE {
        return Err(MALFORMED);
    }
    Ok(ClientData {
        kind: raw.kind,
        challenge: raw.challenge,
        origin: raw.origin,
        cross_origin: raw.cross_origin == Some(true) || raw.top_origin.is_some(),
    })
}

impl ClientData {
    /// Right ceremony, made by a page of exactly `origin`, not inside a
    /// cross-origin frame (we never delegate WebAuthn to embedders).
    pub fn check(&self, ceremony: Ceremony, origin: &str) -> Result<(), WebauthnError> {
        if self.kind != ceremony.type_name() {
            return Err(WebauthnError::WrongType);
        }
        if self.origin != origin {
            return Err(WebauthnError::WrongOrigin);
        }
        if self.cross_origin {
            return Err(WebauthnError::CrossOrigin);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://acme.id.example.com";

    fn json(kind: &str, origin: &str, extra: &str) -> Vec<u8> {
        format!(r#"{{"type":"{kind}","challenge":"Y2g","origin":"{origin}"{extra}}}"#).into_bytes()
    }

    #[test]
    fn accepts_the_expected_ceremony() {
        let cd = parse(&json(
            "webauthn.get",
            ORIGIN,
            r#","crossOrigin":false,"x":1"#,
        ))
        .unwrap();
        assert_eq!(cd.challenge, "Y2g");
        assert!(cd.check(Ceremony::Get, ORIGIN).is_ok());
        assert_eq!(
            cd.check(Ceremony::Create, ORIGIN),
            Err(WebauthnError::WrongType)
        );
    }

    #[test]
    fn origin_must_match_exactly() {
        for origin in [
            "https://acme.id.example.com:443",
            "https://ACME.id.example.com",
            "https://evil.id.example.com",
            "http://acme.id.example.com",
            "https://acme.id.example.com/",
        ] {
            let cd = parse(&json("webauthn.get", origin, "")).unwrap();
            assert_eq!(
                cd.check(Ceremony::Get, ORIGIN),
                Err(WebauthnError::WrongOrigin),
                "{origin}"
            );
        }
    }

    #[test]
    fn cross_origin_is_refused() {
        for extra in [
            r#","crossOrigin":true"#,
            r#","topOrigin":"https://a.example""#,
        ] {
            let cd = parse(&json("webauthn.create", ORIGIN, extra)).unwrap();
            assert_eq!(
                cd.check(Ceremony::Create, ORIGIN),
                Err(WebauthnError::CrossOrigin)
            );
        }
    }

    #[test]
    fn malformed_inputs() {
        let dup = br#"{"type":"webauthn.get","type":"webauthn.get","challenge":"a","origin":"o"}"#;
        assert!(parse(dup).is_err());
        assert!(parse(br#"{"type":"webauthn.get","origin":"o"}"#).is_err());
        assert!(parse(br#"{"type":"webauthn.get","challenge":"","origin":"o"}"#).is_err());
        assert!(parse(b"\xff\xfe").is_err());
        assert!(parse(&vec![b' '; MAX_CLIENT_DATA + 1]).is_err());
        let long = format!(
            r#"{{"type":"t","challenge":"{}","origin":"o"}}"#,
            "a".repeat(129)
        );
        assert!(parse(long.as_bytes()).is_err());
    }
}
