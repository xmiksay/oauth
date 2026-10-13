//! `/api/v1/tenants/{t}/consents` — consent grants. `POST` is Entra's
//! "Grant admin consent": a tenant-wide delegated grant (`user_id: null`)
//! for the requested scopes and, for application permissions, app role
//! assignments to the client app. Only permissions the client declared as
//! required may be granted. `DELETE` withdraws a grant and revokes what the
//! client obtained under it.

use axum::{extract::State, http::StatusCode};
use entity::{app_role_assignments as ara, app_roles, consent_grants};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, TransactionTrait};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    app_rules::find_app,
    apps_permissions::{self, APPLICATION, DELEGATED},
    extract::{Json, Path, Query},
    guard::referenced,
    page::{self, Order, PageParams, Paged},
    role_assignments::{self, Principal, ensure_may_grant_on},
    ts,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    consent,
    error::{AppError, AppResult},
    tokens::refresh,
};

pub fn view(g: &consent_grants::Model) -> Value {
    json!({
        "id": g.id,
        "client_application_id": g.client_application_id,
        "resource_application_id": g.resource_application_id,
        "user_id": g.user_id,
        "scopes": g.scopes,
        "created_at": ts(&g.created_at),
        "updated_at": ts(&g.updated_at),
    })
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    page: PageParams,
    client_application_id: Option<Uuid>,
    resource_application_id: Option<Uuid>,
    user_id: Option<Uuid>,
}

pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    Query(q): Query<ListQuery>,
) -> AppResult<Paged<Value>> {
    caller.require(Area::Applications, Access::Read)?;
    let mut select = consent_grants::Entity::find()
        .filter(consent_grants::Column::TenantId.eq(caller.tenant_id()));
    if let Some(id) = q.client_application_id {
        select = select.filter(consent_grants::Column::ClientApplicationId.eq(id));
    }
    if let Some(id) = q.resource_application_id {
        select = select.filter(consent_grants::Column::ResourceApplicationId.eq(id));
    }
    if let Some(id) = q.user_id {
        select = select.filter(consent_grants::Column::UserId.eq(id));
    }
    let page = page::fetch(
        &state.db,
        select,
        consent_grants::Column::Id,
        q.page.parse()?,
        Order::Ascending,
        |g| g.id,
    )
    .await?;
    Ok(page.map(|g| view(&g)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantBody {
    client_application_id: Uuid,
    resource_application_id: Uuid,
    /// Delegated scope values. With `app_roles` also omitted: everything
    /// the client requires on the resource.
    scopes: Option<Vec<String>>,
    /// Application permission (app role) values.
    app_roles: Option<Vec<String>>,
}

/// `requested` ⊆ `required` (or all of `required` when not given).
fn pick(requested: Option<&[String]>, required: &[String], what: &str) -> AppResult<Vec<String>> {
    match requested {
        None => Ok(required.to_vec()),
        Some(values) => {
            if let Some(missing) = values.iter().find(|v| !required.contains(v)) {
                return Err(AppError::BadRequest(format!(
                    "`{missing}` is not a required {what} of the client on this resource"
                )));
            }
            let mut out = values.to_vec();
            out.sort();
            out.dedup();
            Ok(out)
        }
    }
}

pub async fn grant(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<GrantBody>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Applications, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    let client = referenced(
        find_app(&txn, tenant_id, body.client_application_id).await,
        "client application",
    )?;
    let resource = referenced(
        find_app(&txn, tenant_id, body.resource_application_id).await,
        "resource application",
    )?;
    ensure_may_grant_on(&caller, &resource)?;
    let required = apps_permissions::resolved(&txn, client.id, Some(resource.id)).await?;
    let required_of = |kind: &str| -> Vec<String> {
        required
            .iter()
            .filter(|p| p.kind == kind)
            .map(|p| p.value.clone())
            .collect()
    };
    let explicit = body.scopes.is_some() || body.app_roles.is_some();
    let (scopes, roles) = if explicit {
        (
            pick(
                Some(body.scopes.as_deref().unwrap_or_default()),
                &required_of(DELEGATED),
                "scope",
            )?,
            pick(
                Some(body.app_roles.as_deref().unwrap_or_default()),
                &required_of(APPLICATION),
                "app role",
            )?,
        )
    } else {
        (required_of(DELEGATED), required_of(APPLICATION))
    };
    if scopes.is_empty() && roles.is_empty() {
        return Err(AppError::BadRequest(
            "nothing to grant: the client requires no permissions on this resource".into(),
        ));
    }
    let grant = if scopes.is_empty() {
        None
    } else {
        let id =
            consent::store_grant(&txn, tenant_id, client.id, resource.id, None, &scopes).await?;
        consent_grants::Entity::find_by_id(id).one(&txn).await?
    };
    let mut assignments = Vec::new();
    for value in &roles {
        assignments.push(assign_app_role(&txn, tenant_id, resource.id, client.id, value).await?);
    }
    let details = json!({
        "client_id": client.client_id,
        "resource_client_id": resource.client_id,
        "scopes": scopes,
        "app_roles": roles,
    });
    let target = grant.as_ref().map_or(Target::Application(client.id), |g| {
        Target::ConsentGrant(g.id)
    });
    caller
        .audit(&txn, EventType::ConsentGrant, Some(target), details)
        .await?;
    txn.commit().await?;
    Ok(axum::Json(json!({
        "grant": grant.as_ref().map(view),
        "role_assignments": assignments.iter().map(role_assignments::view).collect::<Vec<_>>(),
    })))
}

/// Idempotent: an existing assignment is returned as is.
async fn assign_app_role(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    resource_id: Uuid,
    client_id: Uuid,
    value: &str,
) -> AppResult<ara::Model> {
    let role = app_roles::Entity::find()
        .filter(app_roles::Column::ApplicationId.eq(resource_id))
        .filter(app_roles::Column::Value.eq(value))
        .one(conn)
        .await?
        .ok_or(AppError::NotFound)?;
    let existing = ara::Entity::find()
        .filter(ara::Column::AppRoleId.eq(role.id))
        .filter(ara::Column::ClientApplicationId.eq(client_id))
        .one(conn)
        .await?;
    match existing {
        Some(found) => Ok(found),
        None => {
            role_assignments::insert(conn, tenant_id, &role, Principal::Application(client_id))
                .await
        }
    }
}

pub async fn revoke(
    State(state): State<AppState>,
    caller: Caller,
    Path((_, id)): Path<(String, Uuid)>,
) -> AppResult<StatusCode> {
    caller.require(Area::Applications, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    let grant = consent_grants::Entity::find_by_id(id)
        .filter(consent_grants::Column::TenantId.eq(tenant_id))
        .one(&txn)
        .await?
        .ok_or(AppError::NotFound)?;
    let resource = find_app(&txn, tenant_id, grant.resource_application_id).await?;
    ensure_may_grant_on(&caller, &resource)?;
    delete_and_revoke(&txn, &grant).await?;
    let details = json!({ "scopes": grant.scopes, "user_id": grant.user_id });
    caller
        .audit(
            &txn,
            EventType::ConsentRevoke,
            Some(Target::ConsentGrant(id)),
            details,
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes the grant and revokes the client's refresh token families and
/// opaque access tokens for the resource — of the grant's user, or of every
/// user for an admin grant (their tokens may rest on it).
pub async fn delete_and_revoke(
    conn: &impl ConnectionTrait,
    grant: &consent_grants::Model,
) -> AppResult<()> {
    consent_grants::Entity::delete_by_id(grant.id)
        .exec(conn)
        .await?;
    refresh::revoke_grant(
        conn,
        grant.tenant_id,
        grant.client_application_id,
        grant.resource_application_id,
        grant.user_id,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_are_limited_to_required_permissions() {
        let req = vec!["a".to_owned(), "b".to_owned()];
        assert_eq!(pick(None, &req, "scope").unwrap(), req);
        assert_eq!(
            pick(Some(&["b".to_owned()]), &req, "scope").unwrap(),
            vec!["b"]
        );
        assert!(pick(Some(&["c".to_owned()]), &req, "scope").is_err());
        assert!(pick(Some(&[]), &req, "scope").unwrap().is_empty());
    }
}
