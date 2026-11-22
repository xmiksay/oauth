//! The writing half of group mappings: memberships a provider's mappings
//! keep, brought in line with a sign-in's [`Mapped`] or dropped.

use std::net::IpAddr;

use anyhow::Context;
use entity::{enums::Outcome, group_members, idp_group_mappings};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, sea_query::Expr,
};
use serde_json::json;
use uuid::Uuid;

use super::{Mapped, Pair, wanted};
use crate::audit::{self, EventType};

pub async fn list(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
) -> anyhow::Result<Vec<idp_group_mappings::Model>> {
    idp_group_mappings::Entity::find()
        .filter(idp_group_mappings::Column::TenantId.eq(tenant_id))
        .filter(idp_group_mappings::Column::IdpId.eq(idp_id))
        .order_by_asc(idp_group_mappings::Column::Id)
        .all(conn)
        .await
        .context("loading group mappings")
}

/// The `(claim, value)` pairs the provider's mappings name: all the ID
/// token check keeps of the token for them.
pub async fn pairs(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
) -> anyhow::Result<Vec<Pair>> {
    idp_group_mappings::Entity::find()
        .select_only()
        .column(idp_group_mappings::Column::Claim)
        .column(idp_group_mappings::Column::Value)
        .distinct()
        .filter(idp_group_mappings::Column::TenantId.eq(tenant_id))
        .filter(idp_group_mappings::Column::IdpId.eq(idp_id))
        .into_tuple()
        .all(conn)
        .await
        .context("loading mapped claim values")
}

/// Memberships a sync added and removed (group ids).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub added: Vec<Uuid>,
    pub removed: Vec<Uuid>,
}

/// [`apply`], one audit event (`group.member_add` / `_remove`, actor the
/// user) per membership changed.
pub async fn sync(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
    user_id: Uuid,
    ip: Option<IpAddr>,
    mapped: &Mapped,
) -> anyhow::Result<Changes> {
    let changes = apply(conn, tenant_id, idp_id, user_id, mapped).await?;
    let added = changes
        .added
        .iter()
        .map(|g| (*g, EventType::GroupMemberAdd));
    let removed = changes
        .removed
        .iter()
        .map(|g| (*g, EventType::GroupMemberRemove));
    for (group_id, event_type) in added.chain(removed) {
        let event = audit::Event {
            tenant_id,
            actor: audit::Actor::User(Some(user_id)),
            event_type,
            target: Some(audit::Target::Group(group_id)),
            outcome: Outcome::Success,
            ip,
            details: json!({ "user_id": user_id, "via": "federation", "idp_id": idp_id }),
        };
        audit::record(conn, event).await?;
    }
    Ok(changes)
}

/// Brings `user_id`'s memberships owned by `idp_id` in line with `mapped`.
/// Run in the sign-in transaction, after `idps::lock_current`: mapping
/// writes lock the provider `FOR UPDATE`, so the mappings read here stay
/// the current ones until it commits.
pub async fn apply(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
    user_id: Uuid,
    mapped: &Mapped,
) -> anyhow::Result<Changes> {
    let (wanted, undecided) = wanted(&list(conn, tenant_id, idp_id).await?, mapped);
    let owned = group_members::Entity::find()
        .filter(group_members::Column::TenantId.eq(tenant_id))
        .filter(group_members::Column::UserId.eq(user_id))
        .filter(group_members::Column::IdpId.eq(idp_id))
        .all(conn)
        .await
        .context("loading mapped memberships")?;
    let mut changes = Changes::default();
    let gone = |m: &&group_members::Model| {
        !wanted.contains(&m.group_id) && !undecided.contains(&m.group_id)
    };
    for row in owned.iter().filter(gone) {
        let filter = sea_orm::Condition::all()
            .add(group_members::Column::TenantId.eq(tenant_id))
            .add(group_members::Column::GroupId.eq(row.group_id))
            .add(group_members::Column::UserId.eq(user_id))
            .add(group_members::Column::IdpId.eq(idp_id));
        if row.manual {
            unmark(conn, filter).await?;
        } else {
            let done = group_members::Entity::delete_many()
                .filter(filter.add(group_members::Column::Manual.eq(false)))
                .exec(conn)
                .await
                .context("removing a mapped membership")?;
            if done.rows_affected > 0 {
                changes.removed.push(row.group_id);
            }
        }
    }
    for group_id in wanted
        .iter()
        .filter(|g| !owned.iter().any(|m| m.group_id == **g))
    {
        if mark(conn, tenant_id, idp_id, user_id, *group_id).await? {
            continue;
        }
        let row = group_members::ActiveModel {
            tenant_id: Set(tenant_id),
            group_id: Set(*group_id),
            user_id: Set(user_id),
            manual: Set(false),
            idp_id: Set(Some(idp_id)),
            ..Default::default()
        };
        // Another provider's membership stays its own.
        let inserted = group_members::Entity::insert(row)
            .on_conflict(
                sea_orm::sea_query::OnConflict::columns([
                    group_members::Column::GroupId,
                    group_members::Column::UserId,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec_without_returning(conn)
            .await
            .context("adding a mapped membership")?;
        if inserted > 0 {
            changes.added.push(*group_id);
        }
    }
    Ok(changes)
}

/// Marks a manual membership (no provider's yet) as kept by `idp_id` too,
/// so the source shows whichever came first; returns whether there was one.
async fn mark(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
    user_id: Uuid,
    group_id: Uuid,
) -> anyhow::Result<bool> {
    let done = group_members::Entity::update_many()
        .col_expr(group_members::Column::IdpId, Expr::value(Some(idp_id)))
        .filter(group_members::Column::TenantId.eq(tenant_id))
        .filter(group_members::Column::GroupId.eq(group_id))
        .filter(group_members::Column::UserId.eq(user_id))
        .filter(group_members::Column::IdpId.is_null())
        .exec(conn)
        .await
        .context("marking a manual membership as mapped")?;
    Ok(done.rows_affected > 0)
}

async fn unmark(conn: &impl ConnectionTrait, filter: sea_orm::Condition) -> anyhow::Result<()> {
    group_members::Entity::update_many()
        .col_expr(
            group_members::Column::IdpId,
            Expr::value(Option::<Uuid>::None),
        )
        .filter(filter.add(group_members::Column::Manual.eq(true)))
        .exec(conn)
        .await
        .context("unmarking a mapped membership")?;
    Ok(())
}

/// Drops the memberships `idp_id`'s mappings keep — of one user (`Some`,
/// an unlinked identity) or of everyone (a repoint, a deleted provider) —
/// and, when `group_id` is given, only in that group (a deleted mapping).
/// Manual ones lose just the mark. Each removal is audited
/// (`group.member_remove` by `actor`); returns how many there were.
pub async fn drop_owned(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
    user_id: Option<Uuid>,
    group_id: Option<Uuid>,
    actor: audit::Actor,
    ip: Option<IpAddr>,
) -> anyhow::Result<u64> {
    let mut filter = sea_orm::Condition::all()
        .add(group_members::Column::TenantId.eq(tenant_id))
        .add(group_members::Column::IdpId.eq(idp_id));
    if let Some(user_id) = user_id {
        filter = filter.add(group_members::Column::UserId.eq(user_id));
    }
    if let Some(group_id) = group_id {
        filter = filter.add(group_members::Column::GroupId.eq(group_id));
    }
    let removed = group_members::Entity::delete_many()
        .filter(filter.clone().add(group_members::Column::Manual.eq(false)))
        .exec_with_returning(conn)
        .await
        .context("dropping mapped memberships")?;
    unmark(conn, filter).await?;
    for row in &removed {
        let event = audit::Event {
            tenant_id,
            actor,
            event_type: EventType::GroupMemberRemove,
            target: Some(audit::Target::Group(row.group_id)),
            outcome: Outcome::Success,
            ip,
            details: json!({ "user_id": row.user_id, "via": "federation", "idp_id": idp_id }),
        };
        audit::record(conn, event).await?;
    }
    Ok(u64::try_from(removed.len()).unwrap_or(u64::MAX))
}
