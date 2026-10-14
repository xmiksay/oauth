//! COSE_Key (RFC 9052/9053, RFC 8230) → AWS-LC verification key, for the
//! three algorithms passkeys use: ES256 (P-256), EdDSA (Ed25519) and RS256
//! (RSA ≥ 2048 bits, PKCS#1 v1.5).

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ED25519, ParsedPublicKey, RSA_PKCS1_2048_8192_SHA256,
    RsaPublicKeyComponents,
};

use super::{ALG_EDDSA, ALG_ES256, ALG_RS256, WebauthnError, cbor};

const KTY: i64 = 1;
const ALG: i64 = 3;
const CRV_OR_N: i64 = -1;
const X_OR_E: i64 = -2;
const Y: i64 = -3;

const KTY_OKP: i64 = 1;
const KTY_EC2: i64 = 2;
const KTY_RSA: i64 = 3;
const CRV_P256: i64 = 1;
const CRV_ED25519: i64 = 6;

pub const RSA_MIN_BITS: usize = 2048;
const RSA_MAX_BITS: usize = 8192;

const MALFORMED: WebauthnError = WebauthnError::Malformed("public key");

/// A credential public key, validated by AWS-LC at parse time.
pub struct CoseKey {
    alg: i64,
    key: ParsedPublicKey,
}

impl std::fmt::Debug for CoseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoseKey").field("alg", &self.alg).finish()
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], WebauthnError> {
    bytes.try_into().map_err(|_| MALFORMED)
}

/// Big-endian unsigned integer without its leading zero bytes.
fn unsigned(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes.get(start..).unwrap_or_default()
}

fn bit_len(n: &[u8]) -> usize {
    n.first()
        .map_or(0, |&top| n.len() * 8 - top.leading_zeros() as usize)
}

impl CoseKey {
    pub fn parse(encoded: &[u8]) -> Result<Self, WebauthnError> {
        let value = cbor::decode_exact(encoded, "public key")?;
        let map = cbor::map(&value, "public key")?;
        let kty = cbor::int(cbor::int_key(map, KTY), "public key")?;
        let alg = cbor::int(cbor::int_key(map, ALG), "public key")?;
        let key = match (kty, alg) {
            (KTY_EC2, ALG_ES256) => {
                if cbor::int(cbor::int_key(map, CRV_OR_N), "public key")? != CRV_P256 {
                    return Err(WebauthnError::UnsupportedAlgorithm);
                }
                let x = fixed::<32>(cbor::bytes(cbor::int_key(map, X_OR_E), "public key")?)?;
                let y = fixed::<32>(cbor::bytes(cbor::int_key(map, Y), "public key")?)?;
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point).map_err(|_| MALFORMED)?
            }
            (KTY_OKP, ALG_EDDSA) => {
                if cbor::int(cbor::int_key(map, CRV_OR_N), "public key")? != CRV_ED25519 {
                    return Err(WebauthnError::UnsupportedAlgorithm);
                }
                let x = fixed::<32>(cbor::bytes(cbor::int_key(map, X_OR_E), "public key")?)?;
                ParsedPublicKey::new(&ED25519, x).map_err(|_| MALFORMED)?
            }
            (KTY_RSA, ALG_RS256) => {
                let n = unsigned(cbor::bytes(cbor::int_key(map, CRV_OR_N), "public key")?);
                let e = unsigned(cbor::bytes(cbor::int_key(map, X_OR_E), "public key")?);
                let bits = bit_len(n);
                if bits < RSA_MIN_BITS {
                    return Err(WebauthnError::WeakKey);
                }
                if bits > RSA_MAX_BITS || e.is_empty() || e.len() > 8 {
                    return Err(MALFORMED);
                }
                RsaPublicKeyComponents { n, e }
                    .to_parsed_public_key(&RSA_PKCS1_2048_8192_SHA256)
                    .map_err(|_| MALFORMED)?
            }
            _ => return Err(WebauthnError::UnsupportedAlgorithm),
        };
        Ok(Self { alg, key })
    }

    /// COSE algorithm identifier.
    pub fn alg(&self) -> i64 {
        self.alg
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), WebauthnError> {
        self.key
            .verify_sig(message, signature)
            .map_err(|_| WebauthnError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        rand::SystemRandom,
        rsa::{KeyPair as RsaKeyPair, KeySize},
        signature::{
            ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256,
        },
    };
    use ciborium::Value;

    use super::*;

    fn cose(entries: Vec<(i64, Value)>) -> Vec<u8> {
        let map = entries
            .into_iter()
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect();
        let mut out = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    }

    fn int(i: i64) -> Value {
        Value::Integer(i.into())
    }

    #[test]
    fn es256_round_trip() {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let point = pair.public_key().as_ref();
        let encoded = cose(vec![
            (KTY, int(KTY_EC2)),
            (ALG, int(ALG_ES256)),
            (CRV_OR_N, int(CRV_P256)),
            (X_OR_E, Value::Bytes(point[1..33].to_vec())),
            (Y, Value::Bytes(point[33..].to_vec())),
        ]);
        let key = CoseKey::parse(&encoded).unwrap();
        assert_eq!(key.alg(), ALG_ES256);
        let sig = pair.sign(&SystemRandom::new(), b"msg").unwrap();
        assert!(key.verify(b"msg", sig.as_ref()).is_ok());
        assert_eq!(
            key.verify(b"other", sig.as_ref()),
            Err(WebauthnError::BadSignature)
        );
    }

    #[test]
    fn ec_point_off_the_curve_is_rejected() {
        let encoded = cose(vec![
            (KTY, int(KTY_EC2)),
            (ALG, int(ALG_ES256)),
            (CRV_OR_N, int(CRV_P256)),
            (X_OR_E, Value::Bytes(vec![1; 32])),
            (Y, Value::Bytes(vec![2; 32])),
        ]);
        assert_eq!(CoseKey::parse(&encoded).unwrap_err(), MALFORMED);
    }

    #[test]
    fn ed25519_round_trip() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let encoded = cose(vec![
            (KTY, int(KTY_OKP)),
            (ALG, int(ALG_EDDSA)),
            (CRV_OR_N, int(CRV_ED25519)),
            (X_OR_E, Value::Bytes(pair.public_key().as_ref().to_vec())),
        ]);
        let key = CoseKey::parse(&encoded).unwrap();
        assert!(key.verify(b"msg", pair.sign(b"msg").as_ref()).is_ok());
        assert!(key.verify(b"msg", &[0; 64]).is_err());
    }

    #[test]
    fn rsa_2048_round_trip_and_short_keys_rejected() {
        let pair = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let public = pair.public_key();
        let (n, e) = (public.modulus(), public.exponent());
        let encoded = cose(vec![
            (KTY, int(KTY_RSA)),
            (ALG, int(ALG_RS256)),
            (
                CRV_OR_N,
                Value::Bytes(n.big_endian_without_leading_zero().to_vec()),
            ),
            (
                X_OR_E,
                Value::Bytes(e.big_endian_without_leading_zero().to_vec()),
            ),
        ]);
        let key = CoseKey::parse(&encoded).unwrap();
        let mut sig = vec![0; pair.public_modulus_len()];
        pair.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), b"msg", &mut sig)
            .unwrap();
        assert!(key.verify(b"msg", &sig).is_ok());

        let mut short = vec![0xff; 255]; // 2040 bits
        short[254] = 0x01;
        let weak = cose(vec![
            (KTY, int(KTY_RSA)),
            (ALG, int(ALG_RS256)),
            (CRV_OR_N, Value::Bytes(short)),
            (X_OR_E, Value::Bytes(vec![1, 0, 1])),
        ]);
        assert_eq!(CoseKey::parse(&weak).unwrap_err(), WebauthnError::WeakKey);
    }

    #[test]
    fn unsupported_and_mismatched_algorithms() {
        for (kty, alg, crv) in [
            (KTY_EC2, -35, CRV_P256),       // ES384
            (KTY_EC2, ALG_ES256, 2),        // P-384 curve
            (KTY_OKP, ALG_EDDSA, 7),        // Ed448
            (KTY_EC2, ALG_EDDSA, CRV_P256), // alg of another key type
            (4, ALG_ES256, CRV_P256),       // symmetric
        ] {
            let encoded = cose(vec![
                (KTY, int(kty)),
                (ALG, int(alg)),
                (CRV_OR_N, int(crv)),
                (X_OR_E, Value::Bytes(vec![0; 32])),
                (Y, Value::Bytes(vec![0; 32])),
            ]);
            assert_eq!(
                CoseKey::parse(&encoded).unwrap_err(),
                WebauthnError::UnsupportedAlgorithm,
                "{kty} {alg} {crv}"
            );
        }
        let no_alg = cose(vec![(KTY, int(KTY_OKP))]);
        assert_eq!(CoseKey::parse(&no_alg).unwrap_err(), MALFORMED);
    }

    #[test]
    fn bit_lengths() {
        assert_eq!(bit_len(&[]), 0);
        assert_eq!(bit_len(&[0x01]), 1);
        assert_eq!(bit_len(&[0x80, 0]), 16);
        assert_eq!(unsigned(&[0, 0, 5]), &[5]);
        assert_eq!(unsigned(&[0, 0]), &[] as &[u8]);
    }
}
