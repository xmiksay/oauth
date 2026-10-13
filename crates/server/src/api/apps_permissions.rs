//! `…/applications/{id}/required-permissions` — what a client app asks for
//! on a resource: delegated scopes (`type: delegated`) and app roles
//! (`type: application`). Declaring is harmless; consent / role assignment
//! is what grants.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::{app_required_permissions as arp, app_roles, app_scopes, applications};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    app_rules::{MAX_REQUIRED_PERMISSIONS, ensure_below, ensure_not_builtin, find_app, lock_app},
    extract::{Json, Path},
    guard::{conflict_on_unique, referenced},
    ts,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    error::{AppError, AppResult},
};

pub const DELEGATED: &str = "delegated";
pub const APPLICATION: &str = "application";

/// A required permission with its resource and value resolved.
pub struct Resolved {
    pub row: arp::Model,
    pub kind: &'static str,
    pub value: String,
    pub resource_client_id: String,
}

fn view(p: &Resolved) -> Value {
    json!({
        "id": p.row.id,
        "resource_application_id": p.row.resource_application_id,
        "resource_client_id": p.resource_client_id,
        "type": p.kind,
        "permission_id": p.row.scope_id.or(p.row.app_role_id),
        "value": p.value,
        "created_at": ts(&p.row.created_at),
    })
}

/// The client app's required permissions (optionally on one resource).
pub async fn resolved(
    conn: &impl ConnectionTrait,
    client_app_id: Uuid,
    resource_app_id: Option<Uuid>,
) -> AppResult<Vec<Resolved>> {
    let mut select = arp::Entity::find().filter(arp::Column::ApplicationId.eq(client_app_id));
    if let Some(resource) = resource_app_id {
        select = select.filter(arp::Column::ResourceApplicationId.eq(resource));
    }
    let rows = select.order_by_asc(arp::Column::Id).all(conn).await?;
    let resources: Vec<Uuid> = rows.iter().map(|r| r.resource_application_id).collect();
    let scopes = app_scopes::Entity::find()
        .filter(app_scopes::Column::Id.is_in(rows.iter().filter_map(|r| r.scope_id)))
        .all(conn)
        .await?;
    let roles = app_roles::Entity::find()
        .filter(app_roles::Column::Id.is_in(rows.iter().filter_map(|r| r.app_role_id)))
        .all(conn)
        .await?;
    let apps = applications::Entity::find()
        .filter(applications::Column::Id.is_in(resources))
        .all(conn)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let (kind, value) = match (row.scope_id, row.app_role_id) {
                (Some(id), _) => (DELEGATED, scopes.iter().find(|s| s.id == id)?.value.clone()),
                (None, Some(id)) => (
                    APPLICATION,
                    roles.iter().find(|r| r.id == id)?.value.clone(),
                ),
                (None, None) => return None,
            };
            let resource_client_id = apps
                .iter()
                .find(|a| a.id == row.resource_application_id)?
                .client_id
                .clone();
            Some(Resolved {
                row,
                kind,
                value,
                resource_client_id,
            })
        })
        .collect())
}

pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    Path((_, app_id)): Path<(String, Uuid)>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Applications, Access::Read)?;
    let app = find_app(&state.db, caller.tenant_id(), app_id).await?;
    let items: Vec<Value> = resolved(&state.db, app.id, None)
        .await?
        .iter()
        .map(view)
        .collect();
    Ok(axum::Json(json!({ "items": items })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePermission {
    resource_application_id: Uuid,
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

pub async fn create(
    State(state): State<AppState>,
    caller: Caller,
    Path((_, app_id)): Path<(String, Uuid)>,
    Json(body): Json<CreatePermission>,
) -> AppResult<Response> {
    caller.require(Area::Applications, Access::Write)?;
    let txn = state.db.begin().await?;
    let tenant_id = caller.tenant_id();
    let app = lock_app(&txn, tenant_id, app_id).await?;
    ensure_not_builtin(&app)?;
    let existing = arp::Entity::find()
        .filter(arp::Column::ApplicationId.eq(app.id))
        .count(&txn)
        .await?;
    ensure_below(existing, MAX_REQUIRED_PERMISSIONS, "required permissions")?;
    let resource = referenced(
        find_app(&txn, tenant_id, body.resource_application_id).await,
        "resource application",
    )?;
    let (scope_id, app_role_id) = match body.kind.as_str() {
        DELEGATED => {
            let scope = app_scopes::Entity::find()
                .filter(app_scopes::Column::ApplicationId.eq(resource.id))
                .filter(app_scopes::Column::Value.eq(&body.value))
                .one(&txn)
                .await?
                .ok_or_else(|| {
                    AppError::BadRequest(format!("the resource exposes no scope `{}`", body.value))
                })?;
            (Some(scope.id), None)
        }
        APPLICATION => {
            let role = app_roles::Entity::find()
                .filter(app_roles::Column::ApplicationId.eq(resource.id))
                .filter(app_roles::Column::Value.eq(&body.value))
                .one(&txn)
                .await?
                .ok_or_else(|| {
                    AppError::BadRequest(format!("the resource has no app role `{}`", body.value))
                })?;
            (None, Some(role.id))
        }
        _ => {
            return Err(AppError::BadRequest(
                "type must be `delegated` or `application`".into(),
            ));
        }
    };
    let row = arp::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tenant_id),
        application_id: Set(app.id),
        resource_application_id: Set(resource.id),
        scope_id: Set(scope_id),
        app_role_id: Set(app_role_id),
        ..Default::default()
    };
    let created = arp::Entity::insert(row)
        .exec_with_returning(&txn)
        .await
        .map_err(|e| conflict_on_unique(e, "the app already requires this permission"))?;
    let details = json!({
        "permission_id": created.id,
        "resource_client_id": resource.client_id,
        "type": body.kind,
        "value": body.value,
    });
    caller
        .audit(
            &txn,
            EventType::ApplicationPermissionAdd,
            Some(Target::Application(app.id)),
            details,
        )
        .await?;
    txn.commit().await?;
    let out = Resolved {
        row: created,
        kind: if scope_id.is_some() {
            DELEGATED
        } else {
            APPLICATION
        },
        value: body.value,
        resource_client_id: resource.client_id,
    };
    Ok((StatusCode::CREATED, axum::Json(view(&out))).into_response())
}

pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path((_, app_id, permission_id)): Path<(String, Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    caller.require(Area::Applications, Access::Write)?;
    let txn = state.db.begin().await?;
    let app = find_app(&txn, caller.tenant_id(), app_id).await?;
    ensure_not_builtin(&app)?;
    let removed = arp::Entity::delete_many()
        .filter(arp::Column::ApplicationId.eq(app.id))
        .filter(arp::Column::Id.eq(permission_id))
        .exec(&txn)
        .await?;
    if removed.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    caller
        .audit(
            &txn,
            EventType::ApplicationPermissionRemove,
            Some(Target::Application(app.id)),
            json!({ "permission_id": permission_id }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
