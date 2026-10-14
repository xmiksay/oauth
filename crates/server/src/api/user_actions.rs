//! Admin actions on a user: password reset, MFA reset, sessions.

use axum::{extract::State, http::StatusCode};
use entity::{sessions, user_recovery_codes, user_totp};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    Caller,
    extract::{Json, Path},
    guard::{ensure_can_modify_user, find_user},
    ts,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    directory::{self, password},
    error::AppResult,
};

pub fn session_view(s: &sessions::Model, current: Option<Uuid>) -> Value {
    json!({
        "id": s.id,
        "amr": s.amr,
        "auth_time": ts(&s.auth_time),
        "ip": s.ip,
        "user_agent": s.user_agent,
        "created_at": ts(&s.created_at),
        "expires_at": ts(&s.expires_at),
        "current": current == Some(s.id),
    })
}

/// The user's unexpired sessions, newest first (a handful per user, so
/// unpaginated).
pub async fn list_sessions(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<sessions::Model>> {
    Ok(sessions::Entity::find()
        .filter(sessions::Column::TenantId.eq(tenant_id))
        .filter(sessions::Column::UserId.eq(user_id))
        .filter(sessions::Column::ExpiresAt.gt(chrono::Utc::now().fixed_offset()))
        .order_by_desc(sessions::Column::Id)
        .all(conn)
        .await?)
}

/// Deletes the user's TOTP enrollment and recovery codes.
pub async fn delete_mfa(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    user_totp::Entity::delete_many()
        .filter(user_totp::Column::TenantId.eq(tenant_id))
        .filter(user_totp::Column::UserId.eq(user_id))
        .exec(conn)
        .await?;
    user_recovery_codes::Entity::delete_many()
        .filter(user_recovery_codes::Column::TenantId.eq(tenant_id))
        .filter(user_recovery_codes::Column::UserId.eq(user_id))
        .exec(conn)
        .await?;
    Ok(())
}

/// The password an admin sets: the given one (`must_change` defaults to
/// true), or a generated one-time password, which must always be changed.
pub struct ChosenPassword {
    pub value: Zeroizing<String>,
    pub generated: bool,
    pub must_change: bool,
}

impl ChosenPassword {
    pub fn new(given: Option<String>, must_change: Option<bool>) -> anyhow::Result<Self> {
        Ok(match given {
            Some(value) => Self {
                value: Zeroizing::new(value),
                generated: false,
                must_change: must_change.unwrap_or(true),
            },
            None => Self {
                value: Zeroizing::new(password::generate_one_time()?),
                generated: true,
                must_change: true,
            },
        })
    }

    /// The value to show the admin once: only a generated password.
    pub fn one_time(&self) -> Option<&str> {
        self.generated.then_some(self.value.as_str())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetPassword {
    /// Omitted: a one-time password is generated and returned.
    password: Option<String>,
    /// Defaults to `true`.
    must_change_password: Option<bool>,
}

/// Sets a new password and signs the user out everywhere (sessions,
/// refresh tokens, opaque access tokens — `directory::set_password`).
pub async fn reset_password(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
    Json(body): Json<ResetPassword>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Directory, Access::Write)?;
    let chosen = ChosenPassword::new(body.password, body.must_change_password)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    find_user(&txn, tenant_id, id).await?;
    ensure_can_modify_user(&txn, &caller, id).await?;
    directory::set_password(&txn, tenant_id, id, &chosen.value, chosen.must_change).await?;
    let details = json!({
        "must_change_password": chosen.must_change,
        "generated": chosen.generated,
    });
    caller
        .audit(
            &txn,
            EventType::UserPasswordReset,
            Some(Target::User(id)),
            details,
        )
        .await?;
    txn.commit().await?;
    Ok(axum::Json(json!({
        "one_time_password": chosen.one_time(),
        "must_change_password": chosen.must_change,
    })))
}

/// Removes TOTP and recovery codes: the user signs in with the password
/// only and may enroll again.
pub async fn reset_mfa(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    caller.require(Area::Directory, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    find_user(&txn, tenant_id, id).await?;
    ensure_can_modify_user(&txn, &caller, id).await?;
    delete_mfa(&txn, tenant_id, id).await?;
    caller
        .audit(
            &txn,
            EventType::UserMfaReset,
            Some(Target::User(id)),
            Value::Null,
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn sessions(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Directory, Access::Read)?;
    let conn = &state.db;
    find_user(conn, caller.tenant_id(), id).await?;
    let items: Vec<Value> = list_sessions(conn, caller.tenant_id(), id)
        .await?
        .iter()
        .map(|s| session_view(s, None))
        .collect();
    Ok(axum::Json(json!({ "items": items })))
}

/// Entra `revokeSignInSessions`: every session, refresh token and opaque
/// access token of the user (JWT access tokens expire on their own).
pub async fn revoke_sessions(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    caller.require(Area::Directory, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    find_user(&txn, tenant_id, id).await?;
    ensure_can_modify_user(&txn, &caller, id).await?;
    directory::revoke_credentials(&txn, tenant_id, id, None).await?;
    caller
        .audit(
            &txn,
            EventType::UserSessionsRevoke,
            Some(Target::User(id)),
            Value::Null,
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
