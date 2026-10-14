//! Authentication ceremony (WebAuthn §7.2): signature over
//! `authenticatorData ‖ SHA-256(clientDataJSON)` plus the counter rule.

use aws_lc_rs::digest::{SHA256, digest};

use super::{
    MAX_AUTHENTICATOR_DATA, MAX_SIGNATURE, Rp, WebauthnError, authdata,
    client_data::{Ceremony, ClientData},
    cose::CoseKey,
};

/// What the RP stored about the credential.
pub struct Stored<'a> {
    pub key: &'a CoseKey,
    pub sign_count: u32,
    pub backup_eligible: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Asserted {
    pub sign_count: u32,
    pub backup_state: bool,
}

/// WebAuthn §7.2 step 22: once either side is non-zero the counter must
/// grow; anything else hints at a cloned authenticator. Authenticators
/// that never count (synced passkeys) stay at 0 forever.
pub fn counter_ok(stored: u32, received: u32) -> bool {
    (stored == 0 && received == 0) || received > stored
}

/// Verifies an assertion whose challenge the caller has already matched
/// (and consumed) for a credential it looked up by id.
pub fn verify(
    rp: &Rp,
    client_data: &ClientData,
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    stored: &Stored<'_>,
) -> Result<Asserted, WebauthnError> {
    client_data.check(Ceremony::Get, &rp.origin)?;
    if authenticator_data.len() > MAX_AUTHENTICATOR_DATA || signature.len() > MAX_SIGNATURE {
        return Err(WebauthnError::Malformed("assertion"));
    }
    let data = authdata::parse(authenticator_data)?;
    if data.attested.is_some() {
        return Err(WebauthnError::Malformed("authenticator data"));
    }
    data.check(&rp.id)?;
    // Backup eligibility is fixed when the credential is created (§6.1.3).
    if data.flags.backup_eligible() != stored.backup_eligible {
        return Err(WebauthnError::BackupState);
    }
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(digest(&SHA256, client_data_json).as_ref());
    stored.key.verify(&signed, signature)?;
    // Only after the signature: an unauthenticated request must not be able
    // to raise a clone alarm.
    if !counter_ok(stored.sign_count, data.sign_count) {
        return Err(WebauthnError::SignCountRegression);
    }
    Ok(Asserted {
        sign_count: data.sign_count,
        backup_state: data.flags.backup_state(),
    })
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
    };
    use ciborium::Value;

    use super::*;
    use crate::webauthn::{authdata::Flags, client_data};

    fn int(i: i64) -> Value {
        Value::Integer(i.into())
    }

    #[test]
    fn a_user_verified_assertion_passes_and_each_check_bites() {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let point = pair.public_key().as_ref();
        let mut cose = Vec::new();
        let map = vec![
            (int(1), int(2)),
            (int(3), int(-7)),
            (int(-1), int(1)),
            (int(-2), Value::Bytes(point[1..33].to_vec())),
            (int(-3), Value::Bytes(point[33..].to_vec())),
        ];
        ciborium::ser::into_writer(&Value::Map(map), &mut cose).unwrap();
        let key = CoseKey::parse(&cose).unwrap();
        let rp = Rp {
            id: "acme.example".into(),
            origin: "https://acme.example".into(),
        };
        let cdj = br#"{"type":"webauthn.get","challenge":"Y2g","origin":"https://acme.example"}"#;
        let cd = client_data::parse(cdj).unwrap();
        let sign = |flags: u8, count: u32| {
            let mut data = digest(&SHA256, b"acme.example").as_ref().to_vec();
            data.push(flags);
            data.extend_from_slice(&count.to_be_bytes());
            let mut signed = data.clone();
            signed.extend_from_slice(digest(&SHA256, cdj).as_ref());
            let sig = pair.sign(&SystemRandom::new(), &signed).unwrap();
            (data, sig.as_ref().to_vec())
        };
        let stored = |sign_count, backup_eligible| Stored {
            key: &key,
            sign_count,
            backup_eligible,
        };
        let (data, sig) = sign(Flags::UP | Flags::UV, 5);
        let ok = verify(&rp, &cd, cdj, &data, &sig, &stored(4, false)).unwrap();
        assert_eq!(
            ok,
            Asserted {
                sign_count: 5,
                backup_state: false
            }
        );
        assert_eq!(
            verify(&rp, &cd, cdj, &data, &sig, &stored(5, false)),
            Err(WebauthnError::SignCountRegression)
        );
        assert_eq!(
            verify(&rp, &cd, cdj, &data, &sig, &stored(0, true)),
            Err(WebauthnError::BackupState)
        );
        let mut tampered = data.clone();
        tampered[36] ^= 1;
        assert_eq!(
            verify(&rp, &cd, cdj, &tampered, &sig, &stored(0, false)),
            Err(WebauthnError::BadSignature)
        );
        let (data, sig) = sign(Flags::UP, 9);
        assert_eq!(
            verify(&rp, &cd, cdj, &data, &sig, &stored(0, false)),
            Err(WebauthnError::UserNotVerified)
        );
    }

    #[test]
    fn counter_rule() {
        assert!(counter_ok(0, 0));
        assert!(counter_ok(0, 1));
        assert!(counter_ok(5, 6));
        assert!(!counter_ok(5, 5));
        assert!(!counter_ok(5, 4));
        assert!(!counter_ok(5, 0));
    }
}
