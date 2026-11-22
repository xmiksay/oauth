//! `…/applications/{id}/roles`: app roles (`value` immutable once created).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::{app_roles, applications, enums::member_type};
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
        "managed": r.managed,
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

pub(crate) fn member_types(raw: &[String]) -> AppResult<Vec<String>> {
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

/// A validated new app role.
pub(crate) struct NewRole {
    pub value: String,
    pub display_name: String,
    pub description: String,
    pub allowed_member_types: Vec<String>,
}

/// Inserts a role under the per-app cap (`managed`: created by `oauth apply`).
pub(crate) async fn insert_role(
    conn: &impl ConnectionTrait,
    app: &applications::Model,
    new: NewRole,
    managed: bool,
) -> AppResult<app_roles::Model> {
    let existing = app_roles::Entity::find()
        .filter(app_roles::Column::ApplicationId.eq(app.id))
        .count(conn)
        .await?;
    ensure_below(existing, MAX_ROLES, "app roles")?;
    let row = app_roles::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(app.tenant_id),
        application_id: Set(app.id),
        value: Set(new.value),
        display_name: Set(new.display_name),
        description: Set(new.description),
        allowed_member_types: Set(new.allowed_member_types),
        managed: Set(managed),
        ..Default::default()
    };
    app_roles::Entity::insert(row)
        .exec_with_returning(conn)
        .await
        .map_err(|e| conflict_on_unique(e, "the app already has a role with this value"))
}

/// Sets the given (validated) fields that differ; returns their names.
pub(crate) fn update_role_fields(
    row: &mut app_roles::ActiveModel,
    display_name: Option<String>,
    description: Option<String>,
    allowed_member_types: Option<Vec<String>>,
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if let Some(name) = display_name
        && set_changed(&mut row.display_name, name)
    {
        fields.push("display_name");
    }
    if let Some(d) = description
        && set_changed(&mut row.description, d)
    {
        fields.push("description");
    }
    if let Some(types) = allowed_member_types
        && set_changed(&mut row.allowed_member_types, types)
    {
        fields.push("allowed_member_types");
    }
    fields
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
    let name = display_name(name, "role")?;
    let types = member_types(types)?;
    let description = validate::opt_description(body.description.as_deref())?.unwrap_or_default();
    let txn = state.db.begin().await?;
    let app = writable_app(&txn, &caller, app_id).await?;
    let new = NewRole {
        value: value.clone(),
        display_name: name,
        description,
        allowed_member_types: types,
    };
    let role = insert_role(&txn, &app, new, false).await?;
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
    let description = body
        .description
        .as_deref()
        .map(validate::description)
        .transpose()?;
    let types = body
        .allowed_member_types
        .as_deref()
        .map(member_types)
        .transpose()?;
    let txn = state.db.begin().await?;
    let app = writable_app(&txn, &caller, app_id).await?;
    let role = find_role(&txn, app.id, role_id).await?;
    let mut row: app_roles::ActiveModel = role.clone().into();
    if update_role_fields(&mut row, name, description, types).is_empty() {
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
