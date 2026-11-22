//! `/api/v1/groups` CRUD and `…/members`.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::{group_members, groups, users};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait,
    QueryFilter, Statement, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    extract::{Json, Path, Query},
    guard::{conflict_on_unique, find_user, referenced},
    page::{self, Order, PageParams, Paged},
    search, ts, users as user_api,
    validate::opt_description,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    directory::display_name,
    error::{AppError, AppResult},
};

/// Names are unique per tenant case-insensitively (the only unique index a
/// write can hit), since they can be the `groups` claim.
pub(crate) const NAME_TAKEN: &str = "another group already has this name (letter case is ignored)";

fn view(g: &groups::Model) -> Value {
    json!({
        "id": g.id,
        "display_name": g.display_name,
        "description": g.description,
        "managed": g.managed,
        "created_at": ts(&g.created_at),
        "updated_at": ts(&g.updated_at),
    })
}

pub(crate) async fn find_group(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    id: Uuid,
) -> AppResult<groups::Model> {
    groups::Entity::find_by_id(id)
        .filter(groups::Column::TenantId.eq(tenant_id))
        .one(conn)
        .await?
        .ok_or(AppError::NotFound)
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    page: PageParams,
    search: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    Query(q): Query<ListQuery>,
) -> AppResult<Paged<Value>> {
    caller.require(Area::Directory, Access::Read)?;
    let mut select = groups::Entity::find().filter(groups::Column::TenantId.eq(caller.tenant_id()));
    if let Some(cond) = search(q.search.as_deref(), &[groups::Column::DisplayName])? {
        select = select.filter(cond);
    }
    let page = page::fetch(
        &state.db,
        select,
        groups::Column::Id,
        q.page.parse()?,
        Order::Ascending,
        |g| g.id,
    )
    .await?;
    Ok(page.map(|g| view(&g)))
}

pub async fn get(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Directory, Access::Read)?;
    Ok(axum::Json(view(
        &find_group(&state.db, caller.tenant_id(), id).await?,
    )))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupBody {
    display_name: Option<String>,
    description: Option<String>,
}

pub async fn create(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<GroupBody>,
) -> AppResult<Response> {
    caller.require(Area::Directory, Access::Write)?;
    let name = body
        .display_name
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("display_name is required".into()))?;
    let row = groups::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(caller.tenant_id()),
        display_name: Set(display_name(name, "group")?),
        description: Set(opt_description(body.description.as_deref())?),
        ..Default::default()
    };
    let txn = state.db.begin().await?;
    let group = groups::Entity::insert(row)
        .exec_with_returning(&txn)
        .await
        .map_err(|err| conflict_on_unique(err, NAME_TAKEN))?;
    caller
        .audit(
            &txn,
            EventType::GroupCreate,
            Some(Target::Group(group.id)),
            json!({ "display_name": group.display_name }),
        )
        .await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, axum::Json(view(&group))).into_response())
}

pub async fn update(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
    Json(body): Json<GroupBody>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Directory, Access::Write)?;
    let name = body
        .display_name
        .as_deref()
        .map(|n| display_name(n, "group"))
        .transpose()?;
    let description = opt_description(body.description.as_deref())?;
    let txn = state.db.begin().await?;
    let group = find_group(&txn, caller.tenant_id(), id).await?;
    let mut fields = Vec::new();
    let mut row: groups::ActiveModel = group.clone().into();
    if let Some(name) = name.filter(|n| *n != group.display_name) {
        row.display_name = Set(name);
        fields.push("display_name");
    }
    if body.description.is_some() && description != group.description {
        row.description = Set(description);
        fields.push("description");
    }
    if fields.is_empty() {
        return Ok(axum::Json(view(&group)));
    }
    row.updated_at = Set(chrono::Utc::now().fixed_offset());
    let updated = row
        .update(&txn)
        .await
        .map_err(|err| conflict_on_unique(err, NAME_TAKEN))?;
    caller
        .audit(
            &txn,
            EventType::GroupUpdate,
            Some(Target::Group(id)),
            json!({ "fields": fields }),
        )
        .await?;
    txn.commit().await?;
    Ok(axum::Json(view(&updated)))
}

pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    caller.require(Area::Directory, Access::Write)?;
    let txn = state.db.begin().await?;
    let group = find_group(&txn, caller.tenant_id(), id).await?;
    // Memberships and app role assignments of the group cascade.
    groups::Entity::delete_by_id(id).exec(&txn).await?;
    caller
        .audit(
            &txn,
            EventType::GroupDelete,
            Some(Target::Group(id)),
            json!({ "display_name": group.display_name }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Members as user objects, paginated by user id.
pub async fn members(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
    Query(q): Query<PageParams>,
) -> AppResult<Paged<Value>> {
    caller.require(Area::Directory, Access::Read)?;
    let conn = &state.db;
    let tenant_id = caller.tenant_id();
    find_group(conn, tenant_id, id).await?;
    let select = group_members::Entity::find()
        .filter(group_members::Column::TenantId.eq(tenant_id))
        .filter(group_members::Column::GroupId.eq(id));
    let page = page::fetch(
        conn,
        select,
        group_members::Column::UserId,
        q.parse()?,
        Order::Ascending,
        |m| m.user_id,
    )
    .await?;
    let ids: Vec<Uuid> = page.items.iter().map(|m| m.user_id).collect();
    let found = users::Entity::find()
        .filter(users::Column::TenantId.eq(tenant_id))
        .filter(users::Column::Id.is_in(ids))
        .all(conn)
        .await?;
    // The user plus where the membership comes from: `manual` and/or kept
    // by `idp_id`'s group mappings.
    Ok(page.map(|m| {
        let Some(mut item) = found.iter().find(|u| u.id == m.user_id).map(user_api::view) else {
            return Value::Null;
        };
        if let Some(obj) = item.as_object_mut() {
            obj.insert("manual".into(), m.manual.into());
            obj.insert("idp_id".into(), json!(m.idp_id));
        }
        item
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddMember {
    user_id: Uuid,
}

pub async fn add_member(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
    Json(body): Json<AddMember>,
) -> AppResult<StatusCode> {
    caller.require(Area::Directory, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    find_group(&txn, tenant_id, id).await?;
    referenced(find_user(&txn, tenant_id, body.user_id).await, "user")?;
    // A membership only a group mapping keeps becomes manual too, so it
    // stays when the mapped claim value goes.
    if !insert_member(&txn, tenant_id, id, body.user_id, false).await? {
        return Err(AppError::Conflict("the user is already a member".into()));
    }
    caller
        .audit(
            &txn,
            EventType::GroupMemberAdd,
            Some(Target::Group(id)),
            json!({ "user_id": body.user_id }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Adds `user_id` as a manual member (also over a mapped-only membership);
/// false when it already was one. `managed`: added by `oauth apply`.
pub(crate) async fn insert_member(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    group_id: Uuid,
    user_id: Uuid,
    managed: bool,
) -> AppResult<bool> {
    let added = conn
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            r"INSERT INTO group_members (tenant_id, group_id, user_id, managed)
              VALUES ($1, $2, $3, $4)
              ON CONFLICT (group_id, user_id) DO UPDATE SET manual = true,
                  managed = group_members.managed OR EXCLUDED.managed
              WHERE NOT group_members.manual",
            [
                tenant_id.into(),
                group_id.into(),
                user_id.into(),
                managed.into(),
            ],
        ))
        .await?;
    Ok(added.rows_affected() > 0)
}

pub async fn remove_member(
    State(state): State<AppState>,
    caller: Caller,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    caller.require(Area::Directory, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    let removed = group_members::Entity::delete_many()
        .filter(group_members::Column::TenantId.eq(tenant_id))
        .filter(group_members::Column::GroupId.eq(id))
        .filter(group_members::Column::UserId.eq(user_id))
        .exec(&txn)
        .await?;
    if removed.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    caller
        .audit(
            &txn,
            EventType::GroupMemberRemove,
            Some(Target::Group(id)),
            json!({ "user_id": user_id }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
