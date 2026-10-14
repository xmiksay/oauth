//! `…/applications/{id}/scopes`: the delegated permissions an app exposes.
//! A `value` is immutable once created (grants and tokens refer to it by
//! name; the same holds for app roles in `apps_roles`).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::app_scopes;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, Statement, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    app_rules::{MAX_SCOPES, ensure_below, find_app, writable_app},
    extract::{Json, Path},
    guard::conflict_on_unique,
    set_changed, ts, validate,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    error::{AppError, AppResult},
    tokens::refresh,
};

fn scope_view(s: &app_scopes::Model) -> Value {
    json!({
        "id": s.id,
        "value": s.value,
        "description": s.description,
        "admin_consent_required": s.admin_consent_required,
        "created_at": ts(&s.created_at),
    })
}

pub async fn list_scopes(
    State(state): State<AppState>,
    caller: Caller,
    Path(app_id): Path<Uuid>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Applications, Access::Read)?;
    let app = find_app(&state.db, caller.tenant_id(), app_id).await?;
    let items: Vec<Value> = app_scopes::Entity::find()
        .filter(app_scopes::Column::ApplicationId.eq(app.id))
        .order_by_asc(app_scopes::Column::Id)
        .all(&state.db)
        .await?
        .iter()
        .map(scope_view)
        .collect();
    Ok(axum::Json(json!({ "items": items })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBody {
    value: Option<String>,
    description: Option<String>,
    admin_consent_required: Option<bool>,
}

pub async fn create_scope(
    State(state): State<AppState>,
    caller: Caller,
    Path(app_id): Path<Uuid>,
    Json(body): Json<ScopeBody>,
) -> AppResult<Response> {
    caller.require(Area::Applications, Access::Write)?;
    let value = body
        .value
        .ok_or_else(|| AppError::BadRequest("value is required".into()))?;
    validate::scope_value(&value)?;
    let description = validate::opt_description(body.description.as_deref())?;
    let txn = state.db.begin().await?;
    let app = writable_app(&txn, &caller, app_id).await?;
    let existing = app_scopes::Entity::find()
        .filter(app_scopes::Column::ApplicationId.eq(app.id))
        .count(&txn)
        .await?;
    ensure_below(existing, MAX_SCOPES, "scopes")?;
    let row = app_scopes::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(app.tenant_id),
        application_id: Set(app.id),
        value: Set(value),
        description: Set(description.unwrap_or_default()),
        admin_consent_required: Set(body.admin_consent_required.unwrap_or(false)),
        ..Default::default()
    };
    let scope = app_scopes::Entity::insert(row)
        .exec_with_returning(&txn)
        .await
        .map_err(|e| conflict_on_unique(e, "the app already exposes a scope with this value"))?;
    let details = json!({ "scope_id": scope.id, "value": scope.value });
    let target = Some(Target::Application(app.id));
    caller
        .audit(&txn, EventType::ApplicationScopeAdd, target, details)
        .await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, axum::Json(scope_view(&scope))).into_response())
}

async fn find_scope(
    conn: &impl ConnectionTrait,
    app_id: Uuid,
    id: Uuid,
) -> AppResult<app_scopes::Model> {
    app_scopes::Entity::find_by_id(id)
        .filter(app_scopes::Column::ApplicationId.eq(app_id))
        .one(conn)
        .await?
        .ok_or(AppError::NotFound)
}

pub async fn update_scope(
    State(state): State<AppState>,
    caller: Caller,
    Path((app_id, scope_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<ScopeBody>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Applications, Access::Write)?;
    if body.value.is_some() {
        return Err(AppError::BadRequest(
            "a scope's value can't be changed".into(),
        ));
    }
    let description = validate::opt_description(body.description.as_deref())?;
    let txn = state.db.begin().await?;
    let app = writable_app(&txn, &caller, app_id).await?;
    let scope = find_scope(&txn, app.id, scope_id).await?;
    if body.description.is_none() && body.admin_consent_required.is_none() {
        return Ok(axum::Json(scope_view(&scope)));
    }
    let mut row: app_scopes::ActiveModel = scope.clone().into();
    let mut changed = false;
    if body.description.is_some() {
        changed |= set_changed(&mut row.description, description.unwrap_or_default());
    }
    if let Some(admin) = body.admin_consent_required {
        changed |= set_changed(&mut row.admin_consent_required, admin);
    }
    if !changed {
        return Ok(axum::Json(scope_view(&scope)));
    }
    let scope = row.update(&txn).await?;
    let details = json!({ "scope_id": scope.id, "value": scope.value });
    let target = Some(Target::Application(app.id));
    caller
        .audit(&txn, EventType::ApplicationScopeUpdate, target, details)
        .await?;
    txn.commit().await?;
    Ok(axum::Json(scope_view(&scope)))
}

/// Deletes the scope, the required permissions naming it (FK cascade), its
/// value from existing consent grants of the app, and revokes the refresh
/// families (with their opaque access tokens) whose grant held it.
pub async fn remove_scope(
    State(state): State<AppState>,
    caller: Caller,
    Path((app_id, scope_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    caller.require(Area::Applications, Access::Write)?;
    let txn = state.db.begin().await?;
    let app = writable_app(&txn, &caller, app_id).await?;
    let scope = find_scope(&txn, app.id, scope_id).await?;
    app_scopes::Entity::delete_by_id(scope.id)
        .exec(&txn)
        .await?;
    txn.execute_raw(Statement::from_sql_and_values(
        txn.get_database_backend(),
        "UPDATE consent_grants SET scopes = array_remove(scopes, $1), updated_at = now() \
         WHERE tenant_id = $2 AND resource_application_id = $3 AND $1 = ANY(scopes)",
        [
            scope.value.clone().into(),
            app.tenant_id.into(),
            app.id.into(),
        ],
    ))
    .await?;
    refresh::revoke_by_scope(&txn, app.tenant_id, app.id, &scope.value).await?;
    let details = json!({ "scope_id": scope.id, "value": scope.value });
    let target = Some(Target::Application(app.id));
    caller
        .audit(&txn, EventType::ApplicationScopeRemove, target, details)
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
