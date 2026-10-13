//! Directory facts that become claims: group memberships and app roles.

use anyhow::Context;
use entity::{app_role_assignments, app_roles, enums::member_type, group_members};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, sea_query::Condition,
};
use uuid::Uuid;

pub async fn user_groups(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<Vec<Uuid>> {
    Ok(group_members::Entity::find()
        .filter(group_members::Column::TenantId.eq(tenant_id))
        .filter(group_members::Column::UserId.eq(user_id))
        .order_by_asc(group_members::Column::GroupId)
        .all(conn)
        .await
        .context("loading group memberships")?
        .into_iter()
        .map(|m| m.group_id)
        .collect())
}

/// Roles of `resource_id` assigned to the user directly or via a group
/// (only roles whose `allowed_member_types` include `user`).
pub async fn user_roles(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    resource_id: Uuid,
    user_id: Uuid,
    groups: &[Uuid],
) -> anyhow::Result<Vec<String>> {
    let mut principal = Condition::any().add(app_role_assignments::Column::UserId.eq(user_id));
    if !groups.is_empty() {
        principal = principal.add(app_role_assignments::Column::GroupId.is_in(groups.to_vec()));
    }
    roles_where(conn, tenant_id, resource_id, principal, member_type::USER).await
}

/// Application permissions of `resource_id` granted to the client app.
pub async fn app_roles(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    resource_id: Uuid,
    client_app_id: Uuid,
) -> anyhow::Result<Vec<String>> {
    let principal =
        Condition::all().add(app_role_assignments::Column::ClientApplicationId.eq(client_app_id));
    roles_where(
        conn,
        tenant_id,
        resource_id,
        principal,
        member_type::APPLICATION,
    )
    .await
}

/// Assigned roles, minus any whose `allowed_member_types` exclude the
/// principal kind (an assignment that slipped past validation never turns
/// into a claim of the wrong kind).
async fn roles_where(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    resource_id: Uuid,
    principal: Condition,
    member: &str,
) -> anyhow::Result<Vec<String>> {
    let role_ids: Vec<Uuid> = app_role_assignments::Entity::find()
        .filter(app_role_assignments::Column::TenantId.eq(tenant_id))
        .filter(app_role_assignments::Column::ResourceApplicationId.eq(resource_id))
        .filter(principal)
        .all(conn)
        .await
        .context("loading app role assignments")?
        .into_iter()
        .map(|a| a.app_role_id)
        .collect();
    if role_ids.is_empty() {
        return Ok(Vec::new());
    }
    Ok(app_roles::Entity::find()
        .filter(app_roles::Column::ApplicationId.eq(resource_id))
        .filter(app_roles::Column::Id.is_in(role_ids))
        .order_by_asc(app_roles::Column::Value)
        .all(conn)
        .await
        .context("loading app roles")?
        .into_iter()
        .filter(|r| r.allowed_member_types.iter().any(|m| m == member))
        .map(|r| r.value)
        .collect())
}
