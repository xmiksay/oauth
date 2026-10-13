//! `/api/v1/tenants/{t}/directory-roles`: directory role assignments.
//! Readable by any directory role; assigned and removed by Global Admins
//! (delegated) only — never by app-only tokens.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::{directory_role_assignments as dra, enums::DirectoryRole};
use sea_orm::{
    ActiveEnum, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    extract::{Json, Path, Query},
    guard::{conflict_on_unique, ensure_not_last_global_admin, lock_user, referenced},
    page::{self, Order, PageParams, Paged},
    ts,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    error::{AppError, AppResult},
};

fn view(a: &dra::Model) -> Value {
    json!({
        "id": a.id,
        "user_id": a.user_id,
        "role": a.role.to_value(),
        "created_at": ts(&a.created_at),
    })
}

fn parse_role(raw: &str) -> AppResult<DirectoryRole> {
    DirectoryRole::try_from_value(&raw.to_owned()).map_err(|_| {
        AppError::BadRequest("role must be GlobalAdmin, ApplicationAdmin or UserAdmin".into())
    })
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    page: PageParams,
    user_id: Option<Uuid>,
    role: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    Query(q): Query<ListQuery>,
) -> AppResult<Paged<Value>> {
    caller.require(Area::DirectoryRoles, Access::Read)?;
    let mut select = dra::Entity::find().filter(dra::Column::TenantId.eq(caller.tenant_id()));
    if let Some(user_id) = q.user_id {
        select = select.filter(dra::Column::UserId.eq(user_id));
    }
    if let Some(role) = q.role.as_deref() {
        select = select.filter(dra::Column::Role.eq(parse_role(role)?));
    }
    let page = page::fetch(
        &state.db,
        select,
        dra::Column::Id,
        q.page.parse()?,
        Order::Ascending,
        |a| a.id,
    )
    .await?;
    Ok(page.map(|a| view(&a)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assign {
    user_id: Uuid,
    role: String,
}

pub async fn assign(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<Assign>,
) -> AppResult<Response> {
    caller.require(Area::DirectoryRoles, Access::Write)?;
    let role = parse_role(&body.role)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    referenced(lock_user(&txn, tenant_id, body.user_id).await, "user")?;
    let row = dra::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tenant_id),
        user_id: Set(body.user_id),
        role: Set(role),
        ..Default::default()
    };
    let assignment = dra::Entity::insert(row)
        .exec_with_returning(&txn)
        .await
        .map_err(|err| conflict_on_unique(err, "the user already holds this role"))?;
    caller
        .audit(
            &txn,
            EventType::DirectoryRoleAssign,
            Some(Target::User(body.user_id)),
            json!({ "role": role.to_value(), "assignment_id": assignment.id }),
        )
        .await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, axum::Json(view(&assignment))).into_response())
}

pub async fn unassign(
    State(state): State<AppState>,
    caller: Caller,
    Path((_, id)): Path<(String, Uuid)>,
) -> AppResult<StatusCode> {
    caller.require(Area::DirectoryRoles, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    let assignment = dra::Entity::find_by_id(id)
        .filter(dra::Column::TenantId.eq(tenant_id))
        .one(&txn)
        .await?
        .ok_or(AppError::NotFound)?;
    if assignment.role == DirectoryRole::GlobalAdmin {
        ensure_not_last_global_admin(&txn, tenant_id, assignment.user_id).await?;
    }
    dra::Entity::delete_by_id(id).exec(&txn).await?;
    caller
        .audit(
            &txn,
            EventType::DirectoryRoleUnassign,
            Some(Target::User(assignment.user_id)),
            json!({ "role": assignment.role.to_value(), "assignment_id": id }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
