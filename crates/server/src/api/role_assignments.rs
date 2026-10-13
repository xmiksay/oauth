//! `/api/v1/tenants/{t}/role-assignments` — app roles of a resource app
//! assigned to users, groups (→ `roles` in delegated tokens) or client apps
//! (→ `roles` in client-credentials tokens). Roles of the built-in
//! management API are assignable by Global Admins only: they ARE directory
//! write access.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::{app_role_assignments as ara, app_roles, applications, enums::member_type};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    app_rules::find_app,
    extract::{Json, Path, Query},
    groups::find_group,
    guard::{conflict_on_unique, find_user, referenced},
    page::{self, Order, PageParams, Paged},
    ts,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    error::{AppError, AppResult},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Principal {
    User(Uuid),
    Group(Uuid),
    Application(Uuid),
}

impl Principal {
    fn of(a: &ara::Model) -> Option<Self> {
        match (a.user_id, a.group_id, a.client_application_id) {
            (Some(id), None, None) => Some(Self::User(id)),
            (None, Some(id), None) => Some(Self::Group(id)),
            (None, None, Some(id)) => Some(Self::Application(id)),
            _ => None,
        }
    }

    fn parse(kind: &str, id: Uuid) -> AppResult<Self> {
        match kind {
            "user" => Ok(Self::User(id)),
            "group" => Ok(Self::Group(id)),
            "application" => Ok(Self::Application(id)),
            _ => Err(AppError::BadRequest(
                "principal_type must be user, group or application".into(),
            )),
        }
    }

    fn parts(self) -> (&'static str, Uuid) {
        match self {
            Self::User(id) => ("user", id),
            Self::Group(id) => ("group", id),
            Self::Application(id) => ("application", id),
        }
    }

    /// The `allowed_member_types` entry this principal needs.
    pub fn member_type(self) -> &'static str {
        match self {
            Self::User(_) | Self::Group(_) => member_type::USER,
            Self::Application(_) => member_type::APPLICATION,
        }
    }
}

pub fn view(a: &ara::Model) -> Value {
    let (kind, id) = Principal::of(a).map_or(("unknown", Uuid::nil()), Principal::parts);
    json!({
        "id": a.id,
        "resource_application_id": a.resource_application_id,
        "app_role_id": a.app_role_id,
        "principal_type": kind,
        "principal_id": id,
        "created_at": ts(&a.created_at),
    })
}

/// 403 unless the caller may grant / revoke on `resource`.
pub fn ensure_may_grant_on(caller: &Caller, resource: &applications::Model) -> AppResult<()> {
    if resource.builtin {
        caller.require_global_admin("grant or revoke access to the management API")?;
    }
    Ok(())
}

/// Validates and inserts an assignment of `role` to `principal`.
pub async fn insert(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    role: &app_roles::Model,
    principal: Principal,
) -> AppResult<ara::Model> {
    if !role
        .allowed_member_types
        .iter()
        .any(|m| m == principal.member_type())
    {
        return Err(AppError::BadRequest(format!(
            "role `{}` can't be assigned to a {}",
            role.value,
            principal.parts().0
        )));
    }
    let (user_id, group_id, client_id) = match principal {
        Principal::User(id) => {
            referenced(find_user(conn, tenant_id, id).await, "user")?;
            (Some(id), None, None)
        }
        Principal::Group(id) => {
            referenced(find_group(conn, tenant_id, id).await, "group")?;
            (None, Some(id), None)
        }
        Principal::Application(id) => {
            referenced(find_app(conn, tenant_id, id).await, "application")?;
            (None, None, Some(id))
        }
    };
    let row = ara::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tenant_id),
        resource_application_id: Set(role.application_id),
        app_role_id: Set(role.id),
        user_id: Set(user_id),
        group_id: Set(group_id),
        client_application_id: Set(client_id),
        ..Default::default()
    };
    ara::Entity::insert(row)
        .exec_with_returning(conn)
        .await
        .map_err(|e| conflict_on_unique(e, "the role is already assigned to this principal"))
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    page: PageParams,
    resource_application_id: Option<Uuid>,
    app_role_id: Option<Uuid>,
    principal_id: Option<Uuid>,
}

pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    Query(q): Query<ListQuery>,
) -> AppResult<Paged<Value>> {
    caller.require(Area::Applications, Access::Read)?;
    let mut select = ara::Entity::find().filter(ara::Column::TenantId.eq(caller.tenant_id()));
    if let Some(id) = q.resource_application_id {
        select = select.filter(ara::Column::ResourceApplicationId.eq(id));
    }
    if let Some(id) = q.app_role_id {
        select = select.filter(ara::Column::AppRoleId.eq(id));
    }
    if let Some(id) = q.principal_id {
        select = select.filter(
            sea_orm::Condition::any()
                .add(ara::Column::UserId.eq(id))
                .add(ara::Column::GroupId.eq(id))
                .add(ara::Column::ClientApplicationId.eq(id)),
        );
    }
    let page = page::fetch(
        &state.db,
        select,
        ara::Column::Id,
        q.page.parse()?,
        Order::Ascending,
        |a| a.id,
    )
    .await?;
    Ok(page.map(|a| view(&a)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAssignment {
    app_role_id: Uuid,
    principal_type: String,
    principal_id: Uuid,
}

pub async fn create(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<CreateAssignment>,
) -> AppResult<Response> {
    caller.require(Area::Applications, Access::Write)?;
    let principal = Principal::parse(&body.principal_type, body.principal_id)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    let role = app_roles::Entity::find_by_id(body.app_role_id)
        .filter(app_roles::Column::TenantId.eq(tenant_id))
        .one(&txn)
        .await?
        .ok_or_else(|| AppError::BadRequest("app role not found".into()))?;
    let resource = find_app(&txn, tenant_id, role.application_id).await?;
    ensure_may_grant_on(&caller, &resource)?;
    let assignment = insert(&txn, tenant_id, &role, principal).await?;
    let (kind, id) = principal.parts();
    let details = json!({
        "resource_client_id": resource.client_id,
        "role": role.value,
        "principal_type": kind,
        "principal_id": id,
    });
    caller
        .audit(
            &txn,
            EventType::RoleAssignmentCreate,
            Some(Target::AppRoleAssignment(assignment.id)),
            details,
        )
        .await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, axum::Json(view(&assignment))).into_response())
}

pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path((_, id)): Path<(String, Uuid)>,
) -> AppResult<StatusCode> {
    caller.require(Area::Applications, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    let assignment = ara::Entity::find_by_id(id)
        .filter(ara::Column::TenantId.eq(tenant_id))
        .one(&txn)
        .await?
        .ok_or(AppError::NotFound)?;
    let resource = find_app(&txn, tenant_id, assignment.resource_application_id).await?;
    ensure_may_grant_on(&caller, &resource)?;
    ara::Entity::delete_by_id(id).exec(&txn).await?;
    caller
        .audit(
            &txn,
            EventType::RoleAssignmentDelete,
            Some(Target::AppRoleAssignment(id)),
            json!({ "resource_client_id": resource.client_id, "app_role_id": assignment.app_role_id }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
