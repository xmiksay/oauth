//! JWS signing with the tenant's active key and verification against the
//! tenant's published keys (the same set JWKS serves).

use anyhow::Context;
use entity::{
    enums::{KeyStatus, SigningAlg},
    signing_keys,
};
use jsonwebtoken::{DecodingKey, Validation, jwk::Jwk};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::keys;

/// RFC 9068 §2.1 media type of JWT access tokens. Checking it on input keeps
/// ID tokens from being replayed as access tokens and vice versa.
pub const TYP_ACCESS_TOKEN: &str = "at+jwt";
pub const TYP_ID_TOKEN: &str = "JWT";

pub async fn sign(
    conn: &impl ConnectionTrait,
    master_key: &[u8; 32],
    tenant_id: Uuid,
    alg: SigningAlg,
    typ: &str,
    claims: &Map<String, Value>,
) -> anyhow::Result<String> {
    let key = keys::active_signing_key(conn, master_key, tenant_id, alg).await?;
    let mut header = key.header();
    header.typ = Some(typ.to_owned());
    jsonwebtoken::encode(&header, claims, &key.encoding_key).context("signing token")
}

#[derive(Debug)]
pub enum VerifyError {
    /// Malformed, unknown key, bad signature, wrong issuer/typ, expired.
    Invalid,
    Internal(anyhow::Error),
}

/// Looks like a JWS compact serialization (opaque tokens contain no dots).
pub fn is_jwt(token: &str) -> bool {
    token.bytes().filter(|&b| b == b'.').count() == 2
}

/// Verifies signature, `iss`, `typ` and (if `check_exp`) `exp`. Audience is
/// the caller's business. The key must still be published by the tenant
/// (next / active / retired-but-unexpired).
pub async fn verify(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    issuer: &str,
    token: &str,
    typ: &str,
    check_exp: bool,
) -> Result<Map<String, Value>, VerifyError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| VerifyError::Invalid)?;
    let kid = header.kid.as_deref().ok_or(VerifyError::Invalid)?;
    let typ_ok = header
        .typ
        .as_deref()
        .is_some_and(|t| t.eq_ignore_ascii_case(typ));
    if !typ_ok {
        return Err(VerifyError::Invalid);
    }
    let row = signing_keys::Entity::find()
        .filter(signing_keys::Column::TenantId.eq(tenant_id))
        .filter(signing_keys::Column::Kid.eq(kid))
        .one(conn)
        .await
        .context("loading verification key")
        .map_err(VerifyError::Internal)?
        .ok_or(VerifyError::Invalid)?;
    let now = chrono::Utc::now().fixed_offset();
    let published = row.status != KeyStatus::Retired || row.expires_at.is_some_and(|e| e > now);
    let alg = keys::jwt_algorithm(row.alg);
    if !published || header.alg != alg {
        return Err(VerifyError::Invalid);
    }
    let jwk: Jwk = serde_json::from_value(row.public_jwk)
        .context("stored public JWK is invalid")
        .map_err(VerifyError::Internal)?;
    let key = DecodingKey::from_jwk(&jwk)
        .context("loading public JWK")
        .map_err(VerifyError::Internal)?;
    let mut validation = Validation::new(alg);
    validation.set_issuer(&[issuer]);
    validation.set_required_spec_claims(&["exp", "iss"]);
    validation.validate_aud = false;
    validation.validate_exp = check_exp;
    validation.leeway = 30;
    jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|_| VerifyError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_shape_detection() {
        assert!(is_jwt("a.b.c"));
        assert!(!is_jwt("abcdef"));
        assert!(!is_jwt("a.b"));
        assert!(!is_jwt("a.b.c.d"));
    }
}
