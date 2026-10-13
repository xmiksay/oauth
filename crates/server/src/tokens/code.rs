//! Authorization codes: random, stored hashed, valid 60 s, single use.

use anyhow::Context;
use chrono::{DateTime, Duration, FixedOffset};
use entity::{authorization_codes, sessions};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, sea_query::Expr,
};
use uuid::Uuid;

use crate::{
    oidc::{params::AuthRequest, redirect},
    secret,
};

pub const CODE_TTL_SECS: i64 = 60;

/// Issues a code for `req` and returns the success redirect URL
/// (`code`, `state`, RFC 9207 `iss`).
pub async fn issue_redirect(
    conn: &impl ConnectionTrait,
    issuer: &str,
    client_app_id: Uuid,
    req: &AuthRequest,
    session: &sessions::Model,
) -> anyhow::Result<String> {
    let code = secret::random_token()?;
    let now = chrono::Utc::now().fixed_offset();
    let mut scopes = req.oidc_scopes.clone();
    scopes.extend(req.resource_scopes.iter().cloned());
    let row = authorization_codes::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(session.tenant_id),
        code_hash: Set(secret::hash(&code)),
        application_id: Set(client_app_id),
        user_id: Set(session.user_id),
        session_id: Set(session.id),
        redirect_uri: Set(req.redirect_uri.clone()),
        scopes: Set(scopes),
        resource_application_id: Set(req.resource_id),
        nonce: Set(req.nonce.clone()),
        code_challenge: Set(req.code_challenge.clone()),
        amr: Set(session.amr.clone()),
        auth_time: Set(session.auth_time),
        expires_at: Set(now + Duration::seconds(CODE_TTL_SECS)),
        consumed_at: Set(None),
        ..Default::default()
    };
    authorization_codes::Entity::insert(row)
        .exec_without_returning(conn)
        .await
        .context("storing authorization code")?;
    let mut params = vec![("code", code.as_str())];
    if let Some(state) = &req.state {
        params.push(("state", state));
    }
    params.push(("iss", issuer));
    Ok(redirect::with_params(&req.redirect_uri, &params))
}

pub async fn find(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    code: &str,
) -> anyhow::Result<Option<authorization_codes::Model>> {
    authorization_codes::Entity::find()
        .filter(authorization_codes::Column::TenantId.eq(tenant_id))
        .filter(authorization_codes::Column::CodeHash.eq(secret::hash(code)))
        .one(conn)
        .await
        .context("looking up authorization code")
}

/// Atomically consumes the code; `false` = it was consumed concurrently.
pub async fn consume(conn: &impl ConnectionTrait, id: Uuid) -> anyhow::Result<bool> {
    let result = authorization_codes::Entity::update_many()
        .col_expr(
            authorization_codes::Column::ConsumedAt,
            Expr::current_timestamp(),
        )
        .filter(authorization_codes::Column::Id.eq(id))
        .filter(authorization_codes::Column::ConsumedAt.is_null())
        .exec(conn)
        .await
        .context("consuming authorization code")?;
    Ok(result.rows_affected == 1)
}

pub fn is_expired(row: &authorization_codes::Model, now: DateTime<FixedOffset>) -> bool {
    row.expires_at <= now
}
