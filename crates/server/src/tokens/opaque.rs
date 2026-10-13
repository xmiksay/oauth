//! Opaque (reference) access tokens: 256 random bits handed out, SHA-256
//! stored with the claim set a JWT would have carried.

use anyhow::Context;
use chrono::{DateTime, FixedOffset};
use entity::opaque_access_tokens;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, sea_query::Expr,
};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::secret;

/// What a token was derived from, so code replay / refresh reuse can revoke it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Links {
    pub authorization_code_id: Option<Uuid>,
    pub family_id: Option<Uuid>,
}

pub struct NewOpaque<'a> {
    pub tenant_id: Uuid,
    pub client_app_id: Uuid,
    pub resource_app_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub links: Links,
    pub claims: &'a Map<String, Value>,
    pub expires_at: DateTime<FixedOffset>,
}

pub async fn issue(conn: &impl ConnectionTrait, new: NewOpaque<'_>) -> anyhow::Result<String> {
    let token = secret::random_token()?;
    let row = opaque_access_tokens::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(new.tenant_id),
        token_hash: Set(secret::hash(&token)),
        application_id: Set(new.client_app_id),
        resource_application_id: Set(new.resource_app_id),
        user_id: Set(new.user_id),
        authorization_code_id: Set(new.links.authorization_code_id),
        family_id: Set(new.links.family_id),
        claims: Set(Value::Object(new.claims.clone())),
        expires_at: Set(new.expires_at),
        revoked_at: Set(None),
        ..Default::default()
    };
    opaque_access_tokens::Entity::insert(row)
        .exec_without_returning(conn)
        .await
        .context("storing opaque access token")?;
    Ok(token)
}

/// The token row if it exists in this tenant, regardless of state. Looked up
/// by hash: comparing hashes of 256-bit secrets leaks nothing useful.
pub async fn find(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    token: &str,
) -> anyhow::Result<Option<opaque_access_tokens::Model>> {
    opaque_access_tokens::Entity::find()
        .filter(opaque_access_tokens::Column::TenantId.eq(tenant_id))
        .filter(opaque_access_tokens::Column::TokenHash.eq(secret::hash(token)))
        .one(conn)
        .await
        .context("looking up opaque access token")
}

pub fn is_active(row: &opaque_access_tokens::Model, now: DateTime<FixedOffset>) -> bool {
    row.revoked_at.is_none() && row.expires_at > now
}

pub async fn revoke(conn: &impl ConnectionTrait, id: Uuid) -> anyhow::Result<()> {
    revoke_where(conn, opaque_access_tokens::Column::Id.eq(id)).await
}

pub async fn revoke_where(
    conn: &impl ConnectionTrait,
    filter: impl sea_orm::sea_query::IntoCondition,
) -> anyhow::Result<()> {
    opaque_access_tokens::Entity::update_many()
        .col_expr(
            opaque_access_tokens::Column::RevokedAt,
            Expr::current_timestamp(),
        )
        .filter(filter)
        .filter(opaque_access_tokens::Column::RevokedAt.is_null())
        .exec(conn)
        .await
        .context("revoking opaque access tokens")?;
    Ok(())
}
