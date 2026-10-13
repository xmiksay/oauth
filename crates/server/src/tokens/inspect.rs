//! Resolving a presented access token (userinfo, introspection).

use anyhow::Context;
use entity::users;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use serde_json::{Map, Value};
use uuid::Uuid;

use super::{jwt, opaque};
use crate::oidc::scope;

/// A currently valid access token.
pub struct Inspected {
    pub claims: Map<String, Value>,
    /// The resource app it is for (`None` for userinfo tokens).
    pub resource_app_id: Option<Uuid>,
}

/// Claims of a valid access token of this tenant (JWT verified against the
/// tenant's published keys, or opaque looked up), else `None`. Delegated
/// tokens of a user who has since been disabled or deleted are invalid.
pub async fn access_token(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    issuer: &str,
    token: &str,
) -> anyhow::Result<Option<Inspected>> {
    let found = if jwt::is_jwt(token) {
        match jwt::verify(conn, tenant_id, issuer, token, jwt::TYP_ACCESS_TOKEN, true).await {
            Ok(claims) => {
                let aud = claims
                    .get("aud")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let resource = scope::find_resource(conn, tenant_id, aud).await?;
                Some(Inspected {
                    claims,
                    resource_app_id: resource.map(|r| r.id),
                })
            }
            Err(jwt::VerifyError::Invalid) => None,
            Err(jwt::VerifyError::Internal(err)) => return Err(err),
        }
    } else {
        let now = chrono::Utc::now().fixed_offset();
        opaque::find(conn, tenant_id, token)
            .await?
            .filter(|row| opaque::is_active(row, now))
            .and_then(|row| match row.claims {
                Value::Object(claims) => Some(Inspected {
                    claims,
                    resource_app_id: row.resource_application_id,
                }),
                _ => None,
            })
    };
    let Some(found) = found else { return Ok(None) };
    match user_of(&found.claims) {
        Some(user_id) if !user_active(conn, tenant_id, user_id).await? => Ok(None),
        _ => Ok(Some(found)),
    }
}

/// The user behind a delegated token (`idtyp=user`).
pub fn user_of(claims: &Map<String, Value>) -> Option<Uuid> {
    if claims.get("idtyp").and_then(Value::as_str) != Some("user") {
        return None;
    }
    claims
        .get("oid")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

pub async fn user_active(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<bool> {
    Ok(users::Entity::find_by_id(user_id)
        .filter(users::Column::TenantId.eq(tenant_id))
        .one(conn)
        .await
        .context("loading token user")?
        .is_some_and(|u| !u.disabled))
}
