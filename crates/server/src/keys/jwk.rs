//! Public JWKs (RFC 7517) and RFC 7638 thumbprints used as `kid`.

use anyhow::{Context, bail};
use aws_lc_rs::digest::{SHA256, digest};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use entity::enums::SigningAlg;
use serde_json::{Value, json};

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Public key members of a JWK, before `kid`/`alg`/`use` are added.
pub enum PublicParams {
    Rsa { n: String, e: String },
    Ec { x: String, y: String },
}

impl PublicParams {
    /// From big-endian modulus and exponent without leading zeros.
    pub fn rsa(modulus: &[u8], exponent: &[u8]) -> Self {
        Self::Rsa {
            n: b64(modulus),
            e: b64(exponent),
        }
    }

    /// From an uncompressed SEC1 P-256 point (`0x04 || x || y`).
    pub fn p256(point: &[u8]) -> anyhow::Result<Self> {
        let Some((0x04, coords)) = point.split_first() else {
            bail!("expected an uncompressed P-256 point");
        };
        let (x, y) = coords
            .split_at_checked(32)
            .filter(|(_, y)| y.len() == 32)
            .context("P-256 point must be 65 bytes")?;
        Ok(Self::Ec {
            x: b64(x),
            y: b64(y),
        })
    }

    /// RFC 7638 thumbprint: SHA-256 over the required members in lexicographic
    /// order, no whitespace. base64url values need no JSON escaping.
    pub fn thumbprint(&self) -> String {
        let canonical = match self {
            Self::Rsa { n, e } => format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#),
            Self::Ec { x, y } => format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#),
        };
        b64(digest(&SHA256, canonical.as_bytes()).as_ref())
    }

    /// Full public JWK as published in JWKS.
    pub fn to_jwk(&self, kid: &str, alg: SigningAlg) -> Value {
        let mut jwk = match self {
            Self::Rsa { n, e } => json!({ "kty": "RSA", "n": n, "e": e }),
            Self::Ec { x, y } => json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y }),
        };
        if let Some(obj) = jwk.as_object_mut() {
            obj.insert("kid".into(), kid.into());
            obj.insert("alg".into(), alg.as_str().into());
            obj.insert("use".into(), "sig".into());
        }
        jwk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7638_example_thumbprint() {
        // RFC 7638 §3.1 example key.
        let params = PublicParams::Rsa {
            n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".into(),
            e: "AQAB".into(),
        };
        assert_eq!(
            params.thumbprint(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn p256_point_is_split_into_coordinates() {
        let mut point = vec![0x04];
        point.extend([1u8; 32]);
        point.extend([2u8; 32]);
        let PublicParams::Ec { x, y } = PublicParams::p256(&point).unwrap() else {
            panic!("expected EC params");
        };
        assert_eq!(x, b64(&[1; 32]));
        assert_eq!(y, b64(&[2; 32]));
        assert!(PublicParams::p256(&point[..64]).is_err());
        point[0] = 0x02;
        assert!(PublicParams::p256(&point).is_err());
    }

    #[test]
    fn jwk_members() {
        let jwk = PublicParams::Ec {
            x: "xx".into(),
            y: "yy".into(),
        }
        .to_jwk("k1", SigningAlg::Es256);
        assert_eq!(
            jwk,
            json!({"kty":"EC","crv":"P-256","x":"xx","y":"yy","kid":"k1","alg":"ES256","use":"sig"})
        );
    }
}
