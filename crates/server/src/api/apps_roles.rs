//! `…/applications/{id}/roles`: app roles (`value` immutable once created).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::{app_roles, enums::member_type};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    app_rules::{MAX_ROLES, ensure_below, find_app, writable_app},
    extract::{Json, Path},
    guard::conflict_on_unique,
    set_changed, ts, validate,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    directory::display_name,
    error::{AppError, AppResult},
};

fn role_view(r: &app_roles::Model) -> Value {
    json!({
        "id": r.id,
        "value": r.value,
        "display_name": r.display_name,
        "description": r.description,
        "allowed_member_types": r.allowed_member_types,
        "created_at": ts(&r.created_at),
    })
}

pub async fn list_roles(
    State(state): State<AppState>,
    caller: Caller,
    Path(app_id): Path<Uuid>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Applications, Access::Read)?;
    let app = find_app(&state.db, caller.tenant_id(), app_id).await?;
    let items: Vec<Value> = app_roles::Entity::find()
        .filter(app_roles::Column::ApplicationId.eq(app.id))
        .order_by_asc(app_roles::Column::Id)
        .all(&state.db)
        .await?
        .iter()
        .map(role_view)
        .collect();
    Ok(axum::Json(json!({ "items": items })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleBody {
    value: Option<String>,
    display_name: Option<String>,
    description: Option<String>,
    allowed_member_types: Option<Vec<String>>,
}

fn member_types(raw: &[String]) -> AppResult<Vec<String>> {
    const ALLOWED: [&str; 2] = [member_type::USER, member_type::APPLICATION];
    if raw.iter().any(|t| !ALLOWED.contains(&t.as_str())) {
        return Err(AppError::BadRequest(
            "allowed_member_types entries must be `user` or `application`".into(),
        ));
    }
    // A set: canonical order, so a reordered echo of the stored value is no change.
    let out: Vec<String> = ALLOWED
        .iter()
        .filter(|a| raw.iter().any(|t| t == *a))
        .map(|a| (*a).to_owned())
        .collect();
    if out.is_empty() {
        return Err(AppError::BadRequest(
            "allowed_member_types must not be empty".into(),
        ));
    }
    Ok(out)
}

pub async fn create_role(
    State(state): State<AppState>,
    caller: Caller,
    Path(app_id): Path<Uuid>,
    Json(body): Json<RoleBody>,
) -> AppResult<Response> {
    caller.require(Area::Applications, Access::Write)?;
    let (Some(value), Some(name), Some(types)) =
        (&body.value, &body.display_name, &body.allowed_member_types)
    else {
        return Err(AppError::BadRequest(
            "value, display_name and allowed_member_types are required".into(),
        ));
    };
    validate::permission_value(value, "role")?;
    let row_fields = (display_name(name, "role")?, member_types(types)?);
    let description = validate::opt_description(body.description.as_deref())?;
    let txn = state.db.begin().await?;
    let app = writable_app(&txn, &caller, app_id).await?;
    let existing = app_roles::Entity::find()
        .filter(app_roles::Column::ApplicationId.eq(app.id))
        .count(&txn)
        .await?;
    ensure_below(existing, MAX_ROLES, "app roles")?;
    let row = app_roles::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(app.tenant_id),
        application_id: Set(app.id),
        value: Set(value.clone()),
        display_name: Set(row_fields.0),
        description: Set(description.unwrap_or_default()),
        allowed_member_types: Set(row_fields.1),
        ..Default::default()
    };
    let role = app_roles::Entity::insert(row)
        .exec_with_returning(&txn)
        .await
        .map_err(|e| conflict_on_unique(e, "the app already has a role with this value"))?;
    let details = json!({ "role_id": role.id, "value": role.value });
    caller
        .audit(
            &txn,
            EventType::ApplicationRoleAdd,
            Some(Target::Application(app.id)),
            details,
        )
        .await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, axum::Json(role_view(&role))).into_response())
}

async fn find_role(
    conn: &impl ConnectionTrait,
    app_id: Uuid,
    id: Uuid,
) -> AppResult<app_roles::Model> {
    app_roles::Entity::find_by_id(id)
        .filter(app_roles::Column::ApplicationId.eq(app_id))
        .one(conn)
        .await?
        .ok_or(AppError::NotFound)
}

pub async fn update_role(
    State(state): State<AppState>,
    caller: Caller,
    Path((app_id, role_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RoleBody>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Applications, Access::Write)?;
    if body.value.is_some() {
        return Err(AppError::BadRequest(
            "a role's value can't be changed".into(),
        ));
    }
    let name = body
        .display_name
        .as_deref()
        .map(|n| display_name(n, "role"))
        .transpose()?;
    let description = validate::opt_description(body.description.as_deref())?;
    let types = body
        .allowed_member_types
        .as_deref()
        .map(member_types)
        .transpose()?;
    let txn = state.db.begin().await?;
    let app = writable_app(&txn, &caller, app_id).await?;
    let role = find_role(&txn, app.id, role_id).await?;
    if name.is_none() && body.description.is_none() && types.is_none() {
        return Ok(axum::Json(role_view(&role)));
    }
    let mut row: app_roles::ActiveModel = role.clone().into();
    let mut changed = false;
    if let Some(name) = name {
        changed |= set_changed(&mut row.display_name, name);
    }
    if body.description.is_some() {
        changed |= set_changed(&mut row.description, description.unwrap_or_default());
    }
    if let Some(types) = types {
        changed |= set_changed(&mut row.allowed_member_types, types);
    }
    if !changed {
        return Ok(axum::Json(role_view(&role)));
    }
    let role = row.update(&txn).await?;
    let details = json!({ "role_id": role.id, "value": role.value });
    caller
        .audit(
            &txn,
            EventType::ApplicationRoleUpdate,
            Some(Target::Application(app.id)),
            details,
        )
        .await?;
    txn.commit().await?;
    Ok(axum::Json(role_view(&role)))
}

/// Deletes the role; its assignments and required permissions cascade.
pub async fn remove_role(
    State(state): State<AppState>,
    caller: Caller,
    Path((app_id, role_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    caller.require(Area::Applications, Access::Write)?;
    let txn = state.db.begin().await?;
    let app = writable_app(&txn, &caller, app_id).await?;
    let role = find_role(&txn, app.id, role_id).await?;
    app_roles::Entity::delete_by_id(role.id).exec(&txn).await?;
    let details = json!({ "role_id": role.id, "value": role.value });
    caller
        .audit(
            &txn,
            EventType::ApplicationRoleRemove,
            Some(Target::Application(app.id)),
            details,
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_types_are_validated_and_deduplicated() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            member_types(&s(&["user", "user", "application"])).unwrap(),
            s(&["user", "application"])
        );
        assert_eq!(
            member_types(&s(&["application", "user"])).unwrap(),
            s(&["user", "application"])
        );
        assert!(member_types(&[]).is_err());
        assert!(member_types(&s(&["group"])).is_err());
    }
}
