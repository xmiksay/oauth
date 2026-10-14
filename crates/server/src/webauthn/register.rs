//! Registration ceremony (WebAuthn §7.1) under the "none" attestation
//! policy: `fmt` and `attStmt` are parsed for shape only and never trusted.

use super::{
    MAX_ATTESTATION_OBJECT, MAX_PUBLIC_KEY, Rp, WebauthnError, authdata, cbor,
    client_data::{Ceremony, ClientData},
    cose::CoseKey,
};

/// A credential ready to be stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registered {
    pub credential_id: Vec<u8>,
    /// The COSE_Key, as sent.
    pub public_key: Vec<u8>,
    pub alg: i64,
    pub sign_count: u32,
    pub aaguid: [u8; 16],
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// Verifies a registration response whose challenge the caller has already
/// matched (and consumed).
pub fn verify(
    rp: &Rp,
    client_data: &ClientData,
    attestation_object: &[u8],
) -> Result<Registered, WebauthnError> {
    const WHAT: &str = "attestation object";
    client_data.check(Ceremony::Create, &rp.origin)?;
    if attestation_object.len() > MAX_ATTESTATION_OBJECT {
        return Err(WebauthnError::Malformed(WHAT));
    }
    let object = cbor::decode_exact(attestation_object, WHAT)?;
    let entries = cbor::map(&object, WHAT)?;
    cbor::text(cbor::text_key(entries, "fmt"), WHAT)?;
    cbor::text_key(entries, "attStmt")
        .and_then(|s| s.as_map())
        .ok_or(WebauthnError::Malformed(WHAT))?;
    let data = authdata::parse(cbor::bytes(cbor::text_key(entries, "authData"), WHAT)?)?;
    data.check(&rp.id)?;
    let credential = data.attested.ok_or(WebauthnError::NoCredential)?;
    if credential.public_key.len() > MAX_PUBLIC_KEY {
        return Err(WebauthnError::Malformed("public key"));
    }
    let key = CoseKey::parse(&credential.public_key)?;
    Ok(Registered {
        credential_id: credential.credential_id,
        public_key: credential.public_key,
        alg: key.alg(),
        sign_count: data.sign_count,
        aaguid: credential.aaguid,
        backup_eligible: data.flags.backup_eligible(),
        backup_state: data.flags.backup_state(),
    })
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        digest::{SHA256, digest},
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
    };
    use ciborium::Value;

    use super::*;
    use crate::webauthn::{authdata::Flags, client_data};

    fn int(i: i64) -> Value {
        Value::Integer(i.into())
    }

    fn encode(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(value, &mut out).unwrap();
        out
    }

    /// An attestation object whose ES256 key carries `padding` extra bytes
    /// in an unknown map entry.
    fn attestation(padding: usize) -> Vec<u8> {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let point = pair.public_key().as_ref();
        let mut key = vec![
            (int(1), int(2)),
            (int(3), int(-7)),
            (int(-1), int(1)),
            (int(-2), Value::Bytes(point[1..33].to_vec())),
            (int(-3), Value::Bytes(point[33..].to_vec())),
        ];
        if padding > 0 {
            key.push((int(100), Value::Bytes(vec![0; padding])));
        }
        let mut data = digest(&SHA256, b"acme.example").as_ref().to_vec();
        data.push(Flags::UP | Flags::UV | Flags::AT);
        data.extend_from_slice(&[0; 4 + 16]);
        data.extend_from_slice(&1u16.to_be_bytes());
        data.push(7);
        data.extend(encode(&Value::Map(key)));
        encode(&Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(data)),
        ]))
    }

    #[test]
    fn oversized_public_keys_are_refused() {
        let rp = Rp {
            id: "acme.example".into(),
            origin: "https://acme.example".into(),
        };
        let cd = client_data::parse(
            br#"{"type":"webauthn.create","challenge":"Y2g","origin":"https://acme.example"}"#,
        )
        .unwrap();
        let ok = verify(&rp, &cd, &attestation(0)).unwrap();
        assert_eq!(ok.credential_id, vec![7]);
        assert!(verify(&rp, &cd, &attestation(1500)).is_ok());
        assert_eq!(
            verify(&rp, &cd, &attestation(MAX_PUBLIC_KEY)),
            Err(WebauthnError::Malformed("public key"))
        );
    }
}
