//! `…/applications/{id}/secrets` — client secrets. A generated value is
//! returned once, at creation; a caller-supplied one (`secret`) is never
//! echoed. Either way only its SHA-256 and a 3-character hint are stored.
//! The tenant policy for non-expiring secrets is re-read `FOR SHARE` inside
//! the create transaction, so a policy switched off mid-request wins.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Duration;
use entity::{applications, client_secrets, enums::ClientType, tenants};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    Caller,
    app_rules::{
        MAX_SECRETS, ensure_below, ensure_may_manage_credentials, ensure_not_builtin, find_app,
        lock_app,
    },
    extract::{Json, Path},
    secret_value, ts,
    validate::opt_description,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    error::{AppError, AppResult},
    secret,
};

/// Entra's default and maximum secret lifetimes.
pub(crate) const DEFAULT_DAYS: i64 = 180;
const MAX_DAYS: i64 = 730;
const HINT_LEN: usize = 3;
const NON_EXPIRING_OFF: &str = "this tenant doesn't allow non-expiring secrets";

/// A generated value's first characters. The server can't tell how much of
/// a supplied value is really random, so its own characters might leak a
/// meaningful part of it: its hint is the start of its SHA-256 in hex instead.
fn hint(value: &str, supplied: bool) -> String {
    if !supplied {
        return value.chars().take(HINT_LEN).collect();
    }
    secret::hash(value)
        .iter()
        .flat_map(|b| [b >> 4, b & 0xf])
        .take(HINT_LEN)
        .filter_map(|n| char::from_digit(u32::from(n), 16))
        .collect()
}

/// The tenant's current policy, its row held `FOR SHARE` until commit so a
/// concurrent settings PATCH serialises with this create.
async fn non_expiring_allowed<C: ConnectionTrait>(conn: &C, tenant_id: Uuid) -> AppResult<bool> {
    tenants::Entity::find_by_id(tenant_id)
        .lock_shared()
        .one(conn)
        .await?
        .map(|t| t.allow_non_expiring_secrets)
        .ok_or(AppError::NotFound)
}

fn view(s: &client_secrets::Model) -> Value {
    json!({
        "id": s.id,
        "hint": s.hint,
        "description": s.description,
        "expires_at": s.expires_at.as_ref().map(ts),
        "never_expires": s.expires_at.is_none(),
        "created_at": ts(&s.created_at),
    })
}

pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    Path(app_id): Path<Uuid>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Applications, Access::Read)?;
    let conn = &state.db;
    find_app(conn, caller.tenant_id(), app_id).await?;
    let items: Vec<Value> = client_secrets::Entity::find()
        .filter(client_secrets::Column::TenantId.eq(caller.tenant_id()))
        .filter(client_secrets::Column::ApplicationId.eq(app_id))
        .order_by_asc(client_secrets::Column::Id)
        .all(conn)
        .await?
        .iter()
        .map(view)
        .collect();
    Ok(axum::Json(json!({ "items": items })))
}

// No Debug: it may carry the caller's secret.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSecret {
    description: Option<String>,
    /// 1-730, default 180.
    expires_in_days: Option<i64>,
    /// No expiry; only where the tenant allows it.
    #[serde(default)]
    never_expires: bool,
    /// Caller-supplied value (config as code) instead of a generated one.
    secret: Option<String>,
}

/// The expiry in days, `None` = never.
fn lifetime(body: &CreateSecret, allow_non_expiring: bool) -> AppResult<Option<i64>> {
    if body.never_expires {
        if body.expires_in_days.is_some() {
            return Err(AppError::BadRequest(
                "expires_in_days and never_expires are exclusive".into(),
            ));
        }
        if !allow_non_expiring {
            return Err(AppError::BadRequest(NON_EXPIRING_OFF.into()));
        }
        return Ok(None);
    }
    let days = body.expires_in_days.unwrap_or(DEFAULT_DAYS);
    if !(1..=MAX_DAYS).contains(&days) {
        return Err(AppError::BadRequest(format!(
            "expires_in_days must be 1-{MAX_DAYS}"
        )));
    }
    Ok(Some(days))
}

pub async fn create(
    State(state): State<AppState>,
    caller: Caller,
    Path(app_id): Path<Uuid>,
    Json(mut body): Json<CreateSecret>,
) -> AppResult<Response> {
    caller.require(Area::Applications, Access::Write)?;
    let supplied = body.secret.take().map(Zeroizing::new);
    let days = lifetime(&body, caller.tenant.allow_non_expiring_secrets)?;
    if let Some(value) = &supplied {
        secret_value::validate(value)?;
    }
    let description = opt_description(body.description.as_deref())?;
    let txn = state.db.begin().await?;
    // `caller.tenant` is the row as of authentication; the check above only
    // fails fast.
    if days.is_none() && !non_expiring_allowed(&txn, caller.tenant_id()).await? {
        return Err(AppError::BadRequest(NON_EXPIRING_OFF.into()));
    }
    let app = lock_app(&txn, caller.tenant_id(), app_id).await?;
    ensure_not_builtin(&app)?;
    if app.client_type == ClientType::Public {
        return Err(AppError::BadRequest(
            "public clients can't have secrets".into(),
        ));
    }
    ensure_may_manage_credentials(&txn, &caller, &app).await?;
    let caller_supplied = supplied.is_some();
    let (created, value) = insert(&txn, &app, days, description, supplied).await?;
    caller
        .audit(
            &txn,
            EventType::ApplicationSecretAdd,
            Some(Target::Application(app.id)),
            json!({
                "secret_id": created.id,
                "never_expires": days.is_none(),
                "caller_supplied": caller_supplied,
            }),
        )
        .await?;
    txn.commit().await?;
    let mut body = view(&created);
    if !caller_supplied && let Some(obj) = body.as_object_mut() {
        obj.insert("secret".into(), value.as_str().into());
    }
    Ok((StatusCode::CREATED, axum::Json(body)).into_response())
}

/// Issues a new secret of the (confidential, locked) `app`, within the
/// per-app cap: `supplied` or a generated value, expiring after `days`
/// (`None` = never); returns the row and the plaintext.
pub(crate) async fn insert(
    conn: &impl ConnectionTrait,
    app: &applications::Model,
    days: Option<i64>,
    description: Option<String>,
    supplied: Option<Zeroizing<String>>,
) -> AppResult<(client_secrets::Model, Zeroizing<String>)> {
    let existing = client_secrets::Entity::find()
        .filter(client_secrets::Column::ApplicationId.eq(app.id))
        .count(conn)
        .await?;
    ensure_below(existing, MAX_SECRETS, "secrets")?;
    let caller_supplied = supplied.is_some();
    let value = match supplied {
        Some(value) => value,
        None => Zeroizing::new(secret::random_token()?),
    };
    let row = client_secrets::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(app.tenant_id),
        application_id: Set(app.id),
        secret_hash: Set(secret::hash(&value)),
        hint: Set(hint(&value, caller_supplied)),
        description: Set(description),
        expires_at: Set(days.map(|d| chrono::Utc::now().fixed_offset() + Duration::days(d))),
        ..Default::default()
    };
    let created = client_secrets::Entity::insert(row)
        .exec_with_returning(conn)
        .await?;
    Ok((created, value))
}

pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path((app_id, secret_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    caller.require(Area::Applications, Access::Write)?;
    let txn = state.db.begin().await?;
    let app = find_app(&txn, caller.tenant_id(), app_id).await?;
    ensure_may_manage_credentials(&txn, &caller, &app).await?;
    let removed = client_secrets::Entity::delete_many()
        .filter(client_secrets::Column::TenantId.eq(app.tenant_id))
        .filter(client_secrets::Column::ApplicationId.eq(app.id))
        .filter(client_secrets::Column::Id.eq(secret_id))
        .exec(&txn)
        .await?;
    if removed.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    caller
        .audit(
            &txn,
            EventType::ApplicationSecretRemove,
            Some(Target::Application(app.id)),
            json!({ "secret_id": secret_id }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(days: Option<i64>, never: bool) -> CreateSecret {
        CreateSecret {
            description: None,
            expires_in_days: days,
            never_expires: never,
            secret: None,
        }
    }

    #[test]
    fn hints() {
        let value = "Zx8pQ2vN7rT4kL9wB3mY6cH1jF5dS0aG";
        assert_eq!(hint(value, false), "Zx8");
        let hashed = hint(value, true);
        assert_eq!(hashed.len(), HINT_LEN);
        assert!(hashed.bytes().all(|b| b.is_ascii_hexdigit()));
        let expected: String = secret::hash(value)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(expected.starts_with(&hashed));
    }

    #[test]
    fn lifetimes() {
        assert_eq!(lifetime(&body(None, false), false).unwrap(), Some(180));
        assert_eq!(lifetime(&body(Some(730), false), false).unwrap(), Some(730));
        assert!(lifetime(&body(Some(731), false), true).is_err());
        assert!(lifetime(&body(Some(0), false), true).is_err());
        assert_eq!(lifetime(&body(None, true), true).unwrap(), None);
        // Tenant policy off, or both asked for.
        assert!(lifetime(&body(None, true), false).is_err());
        assert!(lifetime(&body(Some(30), true), true).is_err());
    }
}
