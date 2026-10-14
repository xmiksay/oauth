//! `…/applications/{id}/secrets` — client secrets. The value is returned
//! once, at creation; only its SHA-256 and a 3-character hint are stored.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Duration;
use entity::{client_secrets, enums::ClientType};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    TransactionTrait,
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
    ts,
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
const DEFAULT_DAYS: i64 = 180;
const MAX_DAYS: i64 = 730;
const HINT_LEN: usize = 3;

fn view(s: &client_secrets::Model) -> Value {
    json!({
        "id": s.id,
        "hint": s.hint,
        "description": s.description,
        "expires_at": s.expires_at.as_ref().map(ts),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSecret {
    description: Option<String>,
    /// 1-730, default 180.
    expires_in_days: Option<i64>,
}

pub async fn create(
    State(state): State<AppState>,
    caller: Caller,
    Path(app_id): Path<Uuid>,
    Json(body): Json<CreateSecret>,
) -> AppResult<Response> {
    caller.require(Area::Applications, Access::Write)?;
    let days = body.expires_in_days.unwrap_or(DEFAULT_DAYS);
    if !(1..=MAX_DAYS).contains(&days) {
        return Err(AppError::BadRequest(format!(
            "expires_in_days must be 1-{MAX_DAYS}"
        )));
    }
    let description = opt_description(body.description.as_deref())?;
    let txn = state.db.begin().await?;
    let app = lock_app(&txn, caller.tenant_id(), app_id).await?;
    ensure_not_builtin(&app)?;
    if app.client_type == ClientType::Public {
        return Err(AppError::BadRequest(
            "public clients can't have secrets".into(),
        ));
    }
    ensure_may_manage_credentials(&txn, &caller, &app).await?;
    let existing = client_secrets::Entity::find()
        .filter(client_secrets::Column::ApplicationId.eq(app.id))
        .count(&txn)
        .await?;
    ensure_below(existing, MAX_SECRETS, "secrets")?;
    let value = Zeroizing::new(secret::random_token()?);
    let hint: String = value.chars().take(HINT_LEN).collect();
    let row = client_secrets::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(app.tenant_id),
        application_id: Set(app.id),
        secret_hash: Set(secret::hash(&value)),
        hint: Set(hint),
        description: Set(description),
        expires_at: Set(Some(
            chrono::Utc::now().fixed_offset() + Duration::days(days),
        )),
        ..Default::default()
    };
    let created = client_secrets::Entity::insert(row)
        .exec_with_returning(&txn)
        .await?;
    caller
        .audit(
            &txn,
            EventType::ApplicationSecretAdd,
            Some(Target::Application(app.id)),
            json!({ "secret_id": created.id }),
        )
        .await?;
    txn.commit().await?;
    let mut body = view(&created);
    if let Some(obj) = body.as_object_mut() {
        obj.insert("secret".into(), value.as_str().into());
    }
    Ok((StatusCode::CREATED, axum::Json(body)).into_response())
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
