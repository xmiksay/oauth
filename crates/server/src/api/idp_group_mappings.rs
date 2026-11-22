//! `/api/v1/identity-providers/{id}/group-mappings` — upstream claim value
//! → local group (`federation::group_map`). Any directory role reads, only
//! a GlobalAdmin writes (`Area::IdentityProviders`). Mappings are created
//! and deleted, never edited. Writes lock the provider `FOR UPDATE`, so a
//! sign-in applying the mappings (`FOR SHARE`) sees all of a change or
//! none of it.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::{groups, idp_group_mappings};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter,
    TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    extract::{Json, Path, Query},
    groups::find_group,
    guard::{conflict_on_unique, referenced},
    identity_providers::lock,
    page::{self, Order, PageParams, Paged},
    ts,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    error::{AppError, AppResult},
    federation::{group_map, idps, profile},
};

fn view(m: &idp_group_mappings::Model, group: Option<&groups::Model>) -> Value {
    json!({
        "id": m.id,
        "idp_id": m.idp_id,
        "claim": m.claim,
        "value": m.value,
        "group_id": m.group_id,
        "group_display_name": group.map(|g| g.display_name.as_str()),
        "created_at": ts(&m.created_at),
    })
}

/// A top-level claim name: 1–64 of `A-Z a-z 0-9 _ . : / -` (the DB CHECK).
pub fn claim_name(raw: &str) -> AppResult<String> {
    let ok = (1..=64).contains(&raw.len())
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:/-".contains(c));
    if ok {
        Ok(raw.to_owned())
    } else {
        Err(AppError::BadRequest(
            "claim must be 1-64 characters of A-Z a-z 0-9 _ . : / -".into(),
        ))
    }
}

/// Kept exactly as given: it is compared with the upstream value as is.
pub fn claim_value(raw: &str) -> AppResult<String> {
    profile::clean_token(raw).ok_or_else(|| {
        AppError::BadRequest("value must be 1-256 bytes without control characters".into())
    })
}

async fn exists(conn: &impl ConnectionTrait, tenant_id: Uuid, idp_id: Uuid) -> AppResult<()> {
    idps::find(conn, tenant_id, idp_id)
        .await?
        .map(|_| ())
        .ok_or(AppError::NotFound)
}

pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    Path(idp_id): Path<Uuid>,
    Query(q): Query<PageParams>,
) -> AppResult<Paged<Value>> {
    caller.require(Area::IdentityProviders, Access::Read)?;
    let conn = &state.db;
    let tenant_id = caller.tenant_id();
    exists(conn, tenant_id, idp_id).await?;
    let select = idp_group_mappings::Entity::find()
        .filter(idp_group_mappings::Column::TenantId.eq(tenant_id))
        .filter(idp_group_mappings::Column::IdpId.eq(idp_id));
    let page = page::fetch(
        conn,
        select,
        idp_group_mappings::Column::Id,
        q.parse()?,
        Order::Ascending,
        |m| m.id,
    )
    .await?;
    let ids: Vec<Uuid> = page.items.iter().map(|m| m.group_id).collect();
    let found = groups::Entity::find()
        .filter(groups::Column::TenantId.eq(tenant_id))
        .filter(groups::Column::Id.is_in(ids))
        .all(conn)
        .await?;
    Ok(page.map(|m| view(&m, found.iter().find(|g| g.id == m.group_id))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewMapping {
    claim: String,
    value: String,
    group_id: Uuid,
}

pub async fn create(
    State(state): State<AppState>,
    caller: Caller,
    Path(idp_id): Path<Uuid>,
    Json(body): Json<NewMapping>,
) -> AppResult<Response> {
    caller.require(Area::IdentityProviders, Access::Write)?;
    let claim = claim_name(&body.claim)?;
    let value = claim_value(&body.value)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    lock(&txn, tenant_id, idp_id).await?;
    let group = referenced(find_group(&txn, tenant_id, body.group_id).await, "group")?;
    let count = idp_group_mappings::Entity::find()
        .filter(idp_group_mappings::Column::TenantId.eq(tenant_id))
        .filter(idp_group_mappings::Column::IdpId.eq(idp_id))
        .count(&txn)
        .await?;
    if count >= group_map::MAX_MAPPINGS {
        return Err(AppError::Conflict(format!(
            "an identity provider can have at most {} group mappings",
            group_map::MAX_MAPPINGS
        )));
    }
    let row = idp_group_mappings::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tenant_id),
        idp_id: Set(idp_id),
        claim: Set(claim),
        value: Set(value),
        group_id: Set(group.id),
        created_at: Set(chrono::Utc::now().fixed_offset()),
    };
    let mapping = idp_group_mappings::Entity::insert(row)
        .exec_with_returning(&txn)
        .await
        .map_err(|err| conflict_on_unique(err, "this mapping exists"))?;
    caller
        .audit(
            &txn,
            EventType::IdpGroupMappingAdd,
            Some(Target::IdentityProvider(idp_id)),
            json!({
                "mapping_id": mapping.id,
                "claim": mapping.claim,
                "value": mapping.value,
                "group_id": group.id,
                "group_display_name": group.display_name,
            }),
        )
        .await?;
    txn.commit().await?;
    Ok((
        StatusCode::CREATED,
        axum::Json(view(&mapping, Some(&group))),
    )
        .into_response())
}

/// Memberships the mapping kept go at once, unless another mapping of the
/// provider grants the same group (the next sign-in sorts those out).
pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path((idp_id, id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    caller.require(Area::IdentityProviders, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    lock(&txn, tenant_id, idp_id).await?;
    let mapping = idp_group_mappings::Entity::find_by_id(id)
        .filter(idp_group_mappings::Column::TenantId.eq(tenant_id))
        .filter(idp_group_mappings::Column::IdpId.eq(idp_id))
        .one(&txn)
        .await?
        .ok_or(AppError::NotFound)?;
    idp_group_mappings::Entity::delete_by_id(id)
        .exec(&txn)
        .await?;
    let still_granted = idp_group_mappings::Entity::find()
        .filter(idp_group_mappings::Column::TenantId.eq(tenant_id))
        .filter(idp_group_mappings::Column::IdpId.eq(idp_id))
        .filter(idp_group_mappings::Column::GroupId.eq(mapping.group_id))
        .count(&txn)
        .await?
        > 0;
    let removed = if still_granted {
        0
    } else {
        group_map::drop_owned(&txn, tenant_id, idp_id, None, Some(mapping.group_id)).await?
    };
    caller
        .audit(
            &txn,
            EventType::IdpGroupMappingRemove,
            Some(Target::IdentityProvider(idp_id)),
            json!({
                "mapping_id": mapping.id,
                "claim": mapping.claim,
                "value": mapping.value,
                "group_id": mapping.group_id,
                "memberships_removed": removed,
            }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_names_and_values() {
        assert_eq!(claim_name("groups").unwrap(), "groups");
        assert!(claim_name("https://x.example/roles").is_ok());
        assert!(claim_name("").is_err());
        assert!(claim_name("a b").is_err());
        assert!(claim_name(&"a".repeat(65)).is_err());
        assert!(claim_name("grüppe").is_err());
        assert_eq!(claim_value(" Eng ").unwrap(), " Eng ");
        assert!(claim_value("").is_err());
        assert!(claim_value("a\u{0}").is_err());
        assert!(claim_value(&"x".repeat(257)).is_err());
    }
}
