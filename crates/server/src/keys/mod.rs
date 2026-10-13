//! Per-tenant token signing keys: generation, sealing at rest, loading the
//! active key and publishing JWKS. Rotation (next → active → retired) is driven
//! by `jobs::rotation`; this module only provides the pieces.
//!
//! RSA keys are 2048-bit: universally interoperable for RS256, NIST-acceptable
//! through 2030, and rotated every `KEY_ROTATION_DAYS` anyway, so 3072-bit's
//! extra margin isn't worth ~3x slower signing on every token issued.
//!
//! All primitives come from AWS-LC (`aws-lc-rs`), also the `jsonwebtoken`
//! backend — one audited provider, and no `rsa` crate (RUSTSEC-2023-0071).
//! Private keys are stored as PKCS#8 DER for both algorithms.

mod jwk;
pub mod wrap;

use anyhow::{Context, anyhow};
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use entity::{
    enums::{KeyStatus, SigningAlg},
    signing_keys,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder,
    sea_query::Condition,
};
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use jwk::PublicParams;

/// A freshly generated key pair, not yet stored.
pub struct GeneratedKey {
    pub kid: String,
    pub alg: SigningAlg,
    /// PKCS#8 DER.
    pub private_der: Zeroizing<Vec<u8>>,
    pub public_jwk: Value,
}

/// A decrypted key ready to sign tokens.
pub struct SigningKey {
    pub kid: String,
    pub alg: SigningAlg,
    pub encoding_key: EncodingKey,
}

impl SigningKey {
    /// JWS header naming this key.
    pub fn header(&self) -> Header {
        let mut header = Header::new(jwt_algorithm(self.alg));
        header.kid = Some(self.kid.clone());
        header
    }
}

pub fn jwt_algorithm(alg: SigningAlg) -> Algorithm {
    match alg {
        SigningAlg::Rs256 => Algorithm::RS256,
        SigningAlg::Es256 => Algorithm::ES256,
    }
}

fn generate_blocking(alg: SigningAlg) -> anyhow::Result<GeneratedKey> {
    let (params, private_der) = match alg {
        SigningAlg::Rs256 => {
            let key = RsaKeyPair::generate(KeySize::Rsa2048)
                .map_err(|_| anyhow!("generating RSA key"))?;
            let der = key.as_der().map_err(|_| anyhow!("encoding RSA key"))?;
            let public = key.public_key();
            (
                PublicParams::rsa(
                    public.modulus().big_endian_without_leading_zero(),
                    public.exponent().big_endian_without_leading_zero(),
                ),
                Zeroizing::new(der.as_ref().to_vec()),
            )
        }
        SigningAlg::Es256 => {
            let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
                .map_err(|_| anyhow!("generating P-256 key"))?;
            let der = key
                .to_pkcs8v1()
                .map_err(|_| anyhow!("encoding P-256 key"))?;
            (
                PublicParams::p256(key.public_key().as_ref())?,
                Zeroizing::new(der.as_ref().to_vec()),
            )
        }
    };
    let kid = params.thumbprint();
    Ok(GeneratedKey {
        public_jwk: params.to_jwk(&kid, alg),
        kid,
        alg,
        private_der,
    })
}

/// Generates a key pair off the async runtime (RSA keygen takes ~100 ms+).
pub async fn generate(alg: SigningAlg) -> anyhow::Result<GeneratedKey> {
    tokio::task::spawn_blocking(move || generate_blocking(alg))
        .await
        .context("key generation task failed")?
}

/// Seals `key` for `tenant_id` and inserts it with `status`.
pub async fn insert(
    conn: &impl ConnectionTrait,
    master_key: &[u8; 32],
    tenant_id: Uuid,
    key: &GeneratedKey,
    status: KeyStatus,
) -> anyhow::Result<signing_keys::Model> {
    let now = chrono::Utc::now().fixed_offset();
    insert_at(conn, master_key, tenant_id, key, status, now).await
}

/// [`insert`] with an explicit creation / activation time (the rotation job
/// runs on its own clock so it can be tested without waiting days).
pub async fn insert_at(
    conn: &impl ConnectionTrait,
    master_key: &[u8; 32],
    tenant_id: Uuid,
    key: &GeneratedKey,
    status: KeyStatus,
    now: chrono::DateTime<chrono::FixedOffset>,
) -> anyhow::Result<signing_keys::Model> {
    let aad = wrap::signing_key_aad(tenant_id, &key.kid);
    let row = signing_keys::ActiveModel {
        created_at: Set(now),
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tenant_id),
        kid: Set(key.kid.clone()),
        alg: Set(key.alg),
        status: Set(status),
        private_key_enc: Set(wrap::seal(master_key, &aad, &key.private_der)?),
        public_jwk: Set(key.public_jwk.clone()),
        activated_at: Set((status == KeyStatus::Active).then_some(now)),
        ..Default::default()
    };
    signing_keys::Entity::insert(row)
        .exec_with_returning(conn)
        .await
        .context("inserting signing key")
}

/// Decrypts a stored key. The AAD is rebuilt from the row itself, so a row
/// whose tenant or kid was altered fails here.
pub fn unseal(master_key: &[u8; 32], row: &signing_keys::Model) -> anyhow::Result<SigningKey> {
    let aad = wrap::signing_key_aad(row.tenant_id, &row.kid);
    let der = wrap::open(master_key, &aad, &row.private_key_enc)
        .with_context(|| format!("unsealing signing key {}", row.kid))?;
    let encoding_key = match row.alg {
        // jsonwebtoken's raw-DER RSA input is PKCS#1, which AWS-LC can't
        // export; its PEM path accepts PKCS#8 and unwraps it.
        SigningAlg::Rs256 => EncodingKey::from_rsa_pem(pkcs8_pem(&der).as_bytes())
            .context("loading RSA signing key")?,
        SigningAlg::Es256 => EncodingKey::from_ec_der(&der),
    };
    Ok(SigningKey {
        kid: row.kid.clone(),
        alg: row.alg,
        encoding_key,
    })
}

fn pkcs8_pem(der: &[u8]) -> Zeroizing<String> {
    const HEADER: &str = "-----BEGIN PRIVATE KEY-----\n";
    const FOOTER: &str = "-----END PRIVATE KEY-----\n";
    let b64 = Zeroizing::new(STANDARD.encode(der));
    // Exact size up front: a reallocation would leave an unzeroized copy.
    let capacity = HEADER.len() + b64.len() + b64.len().div_ceil(64) + FOOTER.len();
    let mut pem = Zeroizing::new(String::with_capacity(capacity));
    pem.push_str(HEADER);
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem.push_str(FOOTER);
    debug_assert_eq!(pem.len(), capacity);
    pem
}

/// The key that currently signs `alg` tokens for the tenant.
pub async fn active_signing_key(
    conn: &impl ConnectionTrait,
    master_key: &[u8; 32],
    tenant_id: Uuid,
    alg: SigningAlg,
) -> anyhow::Result<SigningKey> {
    let row = signing_keys::Entity::find()
        .filter(signing_keys::Column::TenantId.eq(tenant_id))
        .filter(signing_keys::Column::Alg.eq(alg))
        .filter(signing_keys::Column::Status.eq(KeyStatus::Active))
        .one(conn)
        .await
        .context("loading active signing key")?
        .with_context(|| format!("tenant {tenant_id} has no active {} key", alg.as_str()))?;
    unseal(master_key, &row)
}

/// JWKS document: next (pre-published), active and retired keys whose
/// `expires_at` is still in the future — so tokens signed by a just-retired key
/// keep verifying until they expire.
pub async fn jwks(conn: &impl ConnectionTrait, tenant_id: Uuid) -> anyhow::Result<Value> {
    let now = chrono::Utc::now().fixed_offset();
    let rows = signing_keys::Entity::find()
        .filter(signing_keys::Column::TenantId.eq(tenant_id))
        .filter(
            Condition::any()
                .add(signing_keys::Column::Status.is_in([KeyStatus::Next, KeyStatus::Active]))
                .add(
                    Condition::all()
                        .add(signing_keys::Column::Status.eq(KeyStatus::Retired))
                        .add(signing_keys::Column::ExpiresAt.gt(now)),
                ),
        )
        .order_by_asc(signing_keys::Column::CreatedAt)
        .all(conn)
        .await
        .context("loading JWKS")?;
    let keys: Vec<Value> = rows.into_iter().map(|row| row.public_jwk).collect();
    Ok(json!({ "keys": keys }))
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{DecodingKey, Validation, jwk::Jwk};
    use serde_json::json;

    use super::*;

    const MASTER: [u8; 32] = [3; 32];

    fn row_for(tenant_id: Uuid, key: &GeneratedKey) -> signing_keys::Model {
        let aad = wrap::signing_key_aad(tenant_id, &key.kid);
        signing_keys::Model {
            id: Uuid::now_v7(),
            tenant_id,
            kid: key.kid.clone(),
            alg: key.alg,
            status: KeyStatus::Active,
            private_key_enc: wrap::seal(&MASTER, &aad, &key.private_der).unwrap(),
            public_jwk: key.public_jwk.clone(),
            created_at: chrono::Utc::now().fixed_offset(),
            activated_at: None,
            retired_at: None,
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn rs256_jwk_shape() {
        let key = generate(SigningAlg::Rs256).await.unwrap();
        let jwk = &key.public_jwk;
        assert_eq!(jwk["kty"], "RSA");
        assert_eq!(jwk["alg"], "RS256");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["kid"], key.kid.as_str());
        assert_eq!(jwk["e"], "AQAB");
        // 2048-bit modulus = 256 bytes = 342 base64url chars.
        assert_eq!(jwk["n"].as_str().unwrap().len(), 342);
        assert!(jwk.get("d").is_none(), "private member leaked");
    }

    #[tokio::test]
    async fn es256_jwk_shape() {
        let key = generate(SigningAlg::Es256).await.unwrap();
        let jwk = &key.public_jwk;
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["alg"], "ES256");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["x"].as_str().unwrap().len(), 43);
        assert_eq!(jwk["y"].as_str().unwrap().len(), 43);
        assert!(jwk.get("d").is_none(), "private member leaked");
    }

    #[tokio::test]
    async fn sealed_key_signs_and_jwk_verifies() {
        let tenant = Uuid::now_v7();
        for alg in [SigningAlg::Rs256, SigningAlg::Es256] {
            let generated = generate(alg).await.unwrap();
            let signing = unseal(&MASTER, &row_for(tenant, &generated)).unwrap();
            let claims = json!({ "sub": "u1", "exp": 4_000_000_000u64 });
            let token =
                jsonwebtoken::encode(&signing.header(), &claims, &signing.encoding_key).unwrap();

            let jwk: Jwk = serde_json::from_value(generated.public_jwk.clone()).unwrap();
            let header = jsonwebtoken::decode_header(&token).unwrap();
            assert_eq!(header.kid.as_deref(), Some(generated.kid.as_str()));
            let decoded = jsonwebtoken::decode::<Value>(
                &token,
                &DecodingKey::from_jwk(&jwk).unwrap(),
                &Validation::new(jwt_algorithm(alg)),
            )
            .unwrap();
            assert_eq!(decoded.claims["sub"], "u1");

            // A different key of the same alg must not verify it.
            let other = generate(alg).await.unwrap();
            let other_jwk: Jwk = serde_json::from_value(other.public_jwk).unwrap();
            assert!(
                jsonwebtoken::decode::<Value>(
                    &token,
                    &DecodingKey::from_jwk(&other_jwk).unwrap(),
                    &Validation::new(jwt_algorithm(alg)),
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn row_moved_to_another_tenant_cannot_be_unsealed() {
        let generated = generate(SigningAlg::Es256).await.unwrap();
        let mut row = row_for(Uuid::now_v7(), &generated);
        row.tenant_id = Uuid::now_v7();
        assert!(unseal(&MASTER, &row).is_err());
    }
}
