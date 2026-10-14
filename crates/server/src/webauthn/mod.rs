//! WebAuthn Level 3 relying-party verification for passkeys, on AWS-LC
//! (signatures, SHA-256) and `ciborium` (CBOR). Pure: no I/O; the ceremony
//! state (challenges, credentials) lives in `passkey`.
//!
//! Policy: `attestation: "none"` is requested and `attStmt` is ignored
//! whatever its format (nothing about the authenticator is trusted beyond
//! its key); user presence AND user verification are required; the origin
//! must equal the tenant's origin exactly and the RP ID is the tenant host.

pub mod assert;
pub mod authdata;
pub mod cbor;
pub mod client_data;
pub mod cose;
pub mod register;
#[cfg(test)]
mod vectors;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// What the relying party expects of a ceremony on one tenant host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rp {
    /// The tenant host without port (`acme.id.example.com`).
    pub id: String,
    /// The tenant origin (`https://acme.id.example.com[:port]`).
    pub origin: String,
}

/// Size bounds for untrusted inputs, checked before any parsing.
pub const MAX_CLIENT_DATA: usize = 8 * 1024;
pub const MAX_ATTESTATION_OBJECT: usize = 16 * 1024;
pub const MAX_AUTHENTICATOR_DATA: usize = 4 * 1024;
/// RSA-8192 signatures are 1024 bytes; DER ECDSA ≤ 72, Ed25519 64.
pub const MAX_SIGNATURE: usize = 1024;
/// WebAuthn §5.8.3: credential ids are at most 1023 bytes.
pub const MAX_CREDENTIAL_ID: usize = 1023;
/// User handles are at most 64 bytes (ours are 32).
pub const MAX_USER_HANDLE: usize = 64;
/// Largest stored COSE key; the `webauthn_credentials.public_key` CHECK
/// says the same. RSA-8192 needs about 1 KiB, so more is padding.
pub const MAX_PUBLIC_KEY: usize = 2048;

/// Why a ceremony was rejected. `reason()` is a fixed code for audit
/// details (never input).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WebauthnError {
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("wrong client data type")]
    WrongType,
    #[error("origin mismatch")]
    WrongOrigin,
    #[error("cross-origin ceremony")]
    CrossOrigin,
    #[error("RP ID hash mismatch")]
    WrongRpId,
    #[error("user presence missing")]
    UserNotPresent,
    #[error("user verification missing")]
    UserNotVerified,
    #[error("backup state without backup eligibility")]
    BackupState,
    #[error("no attested credential data")]
    NoCredential,
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("key too weak")]
    WeakKey,
    #[error("bad signature")]
    BadSignature,
    #[error("signature counter did not increase")]
    SignCountRegression,
}

impl WebauthnError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::WrongType => "wrong_type",
            Self::WrongOrigin => "wrong_origin",
            Self::CrossOrigin => "cross_origin",
            Self::WrongRpId => "wrong_rp_id",
            Self::UserNotPresent => "user_not_present",
            Self::UserNotVerified => "user_not_verified",
            Self::BackupState => "backup_state",
            Self::NoCredential => "no_credential",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::WeakKey => "weak_key",
            Self::BadSignature => "bad_signature",
            Self::SignCountRegression => "sign_count_regression",
        }
    }
}

/// Decodes base64url (padding tolerated) of at most `max` decoded bytes.
pub fn b64_decode(text: &str, max: usize, what: &'static str) -> Result<Vec<u8>, WebauthnError> {
    let text = text.trim_end_matches('=');
    // 4 chars carry 3 bytes; checked before decoding so huge strings cost nothing.
    if text.len() > max.div_ceil(3) * 4 {
        return Err(WebauthnError::Malformed(what));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| WebauthnError::Malformed(what))?;
    if bytes.len() > max {
        return Err(WebauthnError::Malformed(what));
    }
    Ok(bytes)
}

pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// COSE algorithm identifiers we accept, in order of preference.
pub const ALG_ES256: i64 = -7;
pub const ALG_EDDSA: i64 = -8;
pub const ALG_RS256: i64 = -257;
pub const SUPPORTED_ALGS: [i64; 3] = [ALG_ES256, ALG_EDDSA, ALG_RS256];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_bounds_and_padding() {
        assert_eq!(b64_decode("AQID", 3, "x").unwrap(), vec![1, 2, 3]);
        assert_eq!(b64_decode("AQ==", 3, "x").unwrap(), vec![1]);
        assert_eq!(
            b64_decode("AQID", 2, "x"),
            Err(WebauthnError::Malformed("x"))
        );
        assert!(b64_decode("A+/=", 8, "x").is_err());
        assert!(b64_decode(&"A".repeat(10_000), 16, "x").is_err());
        assert_eq!(b64_encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn reasons_are_snake_case_codes() {
        for err in [
            WebauthnError::Malformed("a"),
            WebauthnError::WrongOrigin,
            WebauthnError::SignCountRegression,
        ] {
            assert!(
                err.reason()
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_')
            );
        }
    }
}
