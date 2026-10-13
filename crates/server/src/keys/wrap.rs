//! AES-256-GCM sealing of secrets at rest under `OAUTH_MASTER_KEY` (AWS-LC).
//!
//! Layout: `nonce (12 B) || ciphertext || tag (16 B)`. The nonce is random
//! (drawn by AWS-LC); with the handful of values sealed per tenant the 2^32
//! random-nonce limit for one key is out of reach.

use anyhow::{Context, anyhow};
use aws_lc_rs::aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use uuid::Uuid;
use zeroize::Zeroizing;

fn key(master_key: &[u8; 32]) -> anyhow::Result<RandomizedNonceKey> {
    RandomizedNonceKey::new(&AES_256_GCM, master_key).map_err(|_| anyhow!("invalid master key"))
}

/// Encrypts `plaintext`, binding it to `aad` (which must be presented again to
/// [`open`]).
pub fn seal(master_key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Room for the tag up front so appending it can't reallocate and leave a
    // plaintext copy behind; zeroized in case sealing fails mid-way.
    let mut in_out = Zeroizing::new(Vec::with_capacity(plaintext.len() + AES_256_GCM.tag_len()));
    in_out.extend_from_slice(plaintext);
    let nonce = key(master_key)?
        .seal_in_place_append_tag(Aad::from(aad), &mut *in_out)
        .map_err(|_| anyhow!("sealing secret"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + in_out.len());
    out.extend_from_slice(nonce.as_ref());
    out.extend_from_slice(&in_out);
    Ok(out)
}

/// Decrypts a [`seal`]ed blob. Fails on a wrong master key, wrong AAD or any
/// tampering — deliberately without saying which.
pub fn open(
    master_key: &[u8; 32],
    aad: &[u8],
    sealed: &[u8],
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let (nonce, ciphertext) = sealed
        .split_first_chunk::<NONCE_LEN>()
        .context("sealed secret is truncated")?;
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let plaintext_len = key(master_key)?
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| anyhow!("unsealing secret failed (wrong OAUTH_MASTER_KEY or tampered row)"))?
        .len();
    buf.truncate(plaintext_len);
    Ok(buf)
}

/// AAD for a signing key: tenant id (16 raw bytes) || kid. Binds the ciphertext
/// to its row, so copying `private_key_enc` to another tenant's row (or kid)
/// makes it undecryptable instead of letting that tenant sign with it.
pub fn signing_key_aad(tenant_id: Uuid, kid: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + kid.len());
    aad.extend_from_slice(tenant_id.as_bytes());
    aad.extend_from_slice(kid.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn roundtrip() {
        let sealed = seal(&KEY, b"aad", b"secret").unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + 6 + 16);
        assert_eq!(open(&KEY, b"aad", &sealed).unwrap().as_slice(), b"secret");
    }

    #[test]
    fn nonce_is_random() {
        assert_ne!(
            seal(&KEY, b"", b"x").unwrap(),
            seal(&KEY, b"", b"x").unwrap()
        );
    }

    #[test]
    fn wrong_aad_fails() {
        let tenant = Uuid::now_v7();
        let sealed = seal(&KEY, &signing_key_aad(tenant, "kid1"), b"secret").unwrap();
        assert!(open(&KEY, &signing_key_aad(tenant, "kid2"), &sealed).is_err());
        assert!(open(&KEY, &signing_key_aad(Uuid::now_v7(), "kid1"), &sealed).is_err());
        assert!(open(&KEY, &signing_key_aad(tenant, "kid1"), &sealed).is_ok());
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&KEY, b"aad", b"secret").unwrap();
        assert!(open(&[8; 32], b"aad", &sealed).is_err());
    }

    #[test]
    fn tampering_and_truncation_fail() {
        let mut sealed = seal(&KEY, b"aad", b"secret").unwrap();
        if let Some(last) = sealed.last_mut() {
            *last ^= 1;
        }
        assert!(open(&KEY, b"aad", &sealed).is_err());
        assert!(open(&KEY, b"aad", &sealed[..5]).is_err());
    }
}
