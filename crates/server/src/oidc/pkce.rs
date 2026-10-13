//! PKCE (RFC 7636), S256 only — `plain` is refused for every client.

use aws_lc_rs::digest::{SHA256, digest};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::secret::ct_eq;

/// An S256 challenge is base64url(SHA-256) without padding: exactly 43 chars.
pub fn valid_challenge(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// RFC 7636 §4.1: 43–128 characters of `[A-Za-z0-9-._~]`.
pub fn valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

pub fn challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()))
}

pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    valid_verifier(verifier) && ct_eq(challenge_for(verifier).as_bytes(), challenge.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7636 Appendix B.
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn rfc7636_vector() {
        assert_eq!(challenge_for(VERIFIER), CHALLENGE);
        assert!(valid_challenge(CHALLENGE));
        assert!(verify_s256(VERIFIER, CHALLENGE));
    }

    #[test]
    fn rejects_wrong_or_malformed_verifiers() {
        let other = format!("{}x", &VERIFIER[..42]);
        assert!(!verify_s256(&other, CHALLENGE));
        assert!(!verify_s256("short", &challenge_for("short")));
        let too_long = "a".repeat(129);
        assert!(!verify_s256(&too_long, &challenge_for(&too_long)));
        let bad_chars = format!("{}+", &VERIFIER[..42]);
        assert!(!valid_verifier(&bad_chars));
        // `plain` would mean challenge == verifier; never accepted.
        assert!(!verify_s256(VERIFIER, VERIFIER));
    }

    #[test]
    fn challenge_shape() {
        assert!(!valid_challenge("abc"));
        assert!(!valid_challenge(&format!("{}=", &CHALLENGE[..42])));
    }
}
