//! Bearer secrets (cookies, codes, tokens): generation, SHA-256 hashing for
//! storage and constant-time comparison. All primitives come from AWS-LC.

use anyhow::anyhow;
use aws_lc_rs::{
    constant_time,
    digest::{SHA256, digest},
    rand,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use uuid::Uuid;

/// 256 random bits, base64url without padding (43 chars).
pub fn random_token() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes).map_err(|_| anyhow!("generating random token"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// A random (version 4) UUID, for handles that must not be guessable.
/// UUIDv7 ids leak their creation time and carry fewer random bits.
pub fn random_uuid() -> anyhow::Result<Uuid> {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes).map_err(|_| anyhow!("generating random id"))?;
    Ok(uuid::Builder::from_random_bytes(bytes).into_uuid())
}

/// SHA-256 of a secret, as stored in the database. Bearer secrets carry 256
/// bits of entropy, so an unsalted fast hash is enough to make a leaked table
/// useless.
pub fn hash(secret: &str) -> Vec<u8> {
    digest(&SHA256, secret.as_bytes()).as_ref().to_vec()
}

/// Constant-time equality (length is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time::verify_slices_are_equal(a, b).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_and_url_safe() {
        let a = random_token().unwrap();
        assert_eq!(a.len(), 43);
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_ne!(a, random_token().unwrap());
    }

    #[test]
    fn random_uuids_are_v4() {
        let id = random_uuid().unwrap();
        assert_eq!(id.get_version_num(), 4);
        assert_ne!(id, random_uuid().unwrap());
    }

    #[test]
    fn hash_is_sha256() {
        // SHA-256("abc"), FIPS 180-2 test vector.
        assert_eq!(
            hash("abc").first_chunk::<4>(),
            Some(&[0xba, 0x78, 0x16, 0xbf])
        );
        assert_eq!(hash("abc").len(), 32);
        assert!(ct_eq(&hash("abc"), &hash("abc")));
        assert!(!ct_eq(&hash("abc"), &hash("abd")));
        assert!(!ct_eq(b"a", b"ab"));
    }
}
