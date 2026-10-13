//! Password hashing (argon2id) and one-time password generation.

use anyhow::{Context, anyhow};
use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use aws_lc_rs::rand;

use super::DirectoryError;

pub const MIN_PASSWORD_LEN: usize = 12;
/// Upper bound so a huge body can't make hashing a DoS vector.
pub const MAX_PASSWORD_LEN: usize = 256;
const ONE_TIME_PASSWORD_LEN: usize = 24;
const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// OWASP Password Storage Cheat Sheet: argon2id, m = 19 MiB, t = 2, p = 1.
fn argon2() -> anyhow::Result<Argon2<'static>> {
    let params = Params::new(19 * 1024, 2, 1, None).map_err(|e| anyhow!("argon2 params: {e}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub fn validate(password: &str) -> Result<(), DirectoryError> {
    let len = password.chars().count();
    if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&len) {
        return Err(DirectoryError::Invalid(format!(
            "password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

/// Hashes on the blocking pool (~tens of ms of CPU by design).
pub async fn hash(password: &str) -> anyhow::Result<String> {
    let password = zeroize::Zeroizing::new(password.to_owned());
    tokio::task::spawn_blocking(move || {
        let mut salt = [0u8; 16];
        rand::fill(&mut salt).map_err(|_| anyhow!("generating salt"))?;
        let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow!("encoding salt: {e}"))?;
        argon2()?
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| anyhow!("hashing password: {e}"))
    })
    .await
    .context("password hashing task failed")?
}

/// Verifies against a stored PHC string (parameters are read from the hash, so
/// old hashes keep verifying after a parameter bump).
pub async fn verify(password: &str, phc: &str) -> anyhow::Result<bool> {
    let password = zeroize::Zeroizing::new(password.to_owned());
    let phc = phc.to_owned();
    tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&phc).map_err(|e| anyhow!("stored hash invalid: {e}"))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    })
    .await
    .context("password verification task failed")?
}

/// Random alphanumeric password (~143 bits) for bootstrap / admin resets.
pub fn generate_one_time() -> anyhow::Result<String> {
    crate::secret::random_string(ALPHABET, ONE_TIME_PASSWORD_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_and_verify() {
        let phc = hash("correct horse battery").await.unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        assert!(verify("correct horse battery", &phc).await.unwrap());
        assert!(!verify("wrong horse battery", &phc).await.unwrap());
    }

    #[tokio::test]
    async fn salts_differ() {
        assert_ne!(
            hash("same password!").await.unwrap(),
            hash("same password!").await.unwrap()
        );
    }

    #[tokio::test]
    async fn malformed_hash_is_an_error() {
        assert!(verify("whatever", "not-a-phc").await.is_err());
    }

    #[test]
    fn length_policy() {
        assert!(validate(&"x".repeat(MIN_PASSWORD_LEN - 1)).is_err());
        assert!(validate(&"x".repeat(MIN_PASSWORD_LEN)).is_ok());
        assert!(validate(&"x".repeat(MAX_PASSWORD_LEN + 1)).is_err());
    }

    #[test]
    fn one_time_passwords_pass_policy_and_differ() {
        let a = generate_one_time().unwrap();
        assert_eq!(a.len(), ONE_TIME_PASSWORD_LEN);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(validate(&a).is_ok());
        assert_ne!(a, generate_one_time().unwrap());
    }
}
