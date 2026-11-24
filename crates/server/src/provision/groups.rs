//! Groups (by name, ignoring letter case) and their managed memberships.

use anyhow::Context;
use entity::{group_members, groups, users};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
};
use serde_json::json;
use uuid::Uuid;

use super::{
    ctx::{Ctx, diff, update_line},
    spec::GroupSpec,
};
use crate::{
    api::{
        groups::{NAME_TAKEN, insert_member},
        guard::conflict_on_unique,
        validate::opt_description,
    },
    audit::{EventType, Target},
    directory::display_name,
};

pub async fn apply(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    specs: &[GroupSpec],
) -> anyhow::Result<()> {
    for spec in specs {
        let what = || format!("group `{}`", spec.display_name);
        let group = upsert(conn, cx, spec).await.with_context(what)?;
        members(conn, cx, &group, &spec.members)
            .await
            .with_context(what)?;
    }
    Ok(())
}

async fn upsert(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    spec: &GroupSpec,
) -> anyhow::Result<groups::Model> {
    let name = display_name(&spec.display_name, "group")?;
    let description = opt_description(spec.description.as_deref())?;
    let Some(group) = cx.find_group(conn, &name).await? else {
        let row = groups::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(cx.tenant_id),
            display_name: Set(name),
            description: Set(description),
            managed: Set(true),
            ..Default::default()
        };
        let group = groups::Entity::insert(row)
            .exec_with_returning(conn)
            .await
            .map_err(|err| conflict_on_unique(err, NAME_TAKEN))?;
        cx.kept.insert(group.id);
        let line = format!("+ group {}", group.display_name);
        let details = json!({ "display_name": group.display_name });
        let target = Some(Target::Group(group.id));
        cx.record(conn, line, EventType::GroupCreate, target, details)
            .await?;
        return Ok(group);
    };
    cx.kept.insert(group.id);
    let mut row: groups::ActiveModel = group.clone().into();
    let mut fields = Vec::new();
    if name != group.display_name {
        row.display_name = Set(name);
        fields.push("display_name");
    }
    if spec.description.is_some() && description != group.description {
        row.description = Set(description);
        fields.push("description");
    }
    if fields.is_empty() && group.managed {
        return Ok(group);
    }
    row.managed = Set(true);
    if !fields.is_empty() {
        row.updated_at = Set(chrono::Utc::now().fixed_offset());
    }
    let updated = row.update(conn).await?;
    let line = update_line(
        &format!("group {}", group.display_name),
        &diff(&group, &updated, &fields),
        !group.managed,
    );
    if fields.is_empty() {
        cx.note(line);
    } else {
        let target = Some(Target::Group(group.id));
        let details = json!({ "fields": fields });
        cx.record(conn, line, EventType::GroupUpdate, target, details)
            .await?;
    }
    Ok(updated)
}

/// Members the file lists become manual, managed members; managed members
/// it no longer lists leave ([`release`]).
async fn members(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    group: &groups::Model,
    emails: &[String],
) -> anyhow::Result<()> {
    let tenant_id = cx.tenant_id;
    let mut wanted = Vec::new();
    for email in emails {
        wanted.push(cx.user(conn, email).await?);
    }
    let existing = group_members::Entity::find()
        .filter(group_members::Column::TenantId.eq(tenant_id))
        .filter(group_members::Column::GroupId.eq(group.id))
        .all(conn)
        .await?;
    let target = Some(Target::Group(group.id));
    for user in &wanted {
        let line = format!("member {} of {}", user.email, group.display_name);
        match existing.iter().find(|m| m.user_id == user.id) {
            Some(m) if m.manual && m.managed => {}
            Some(m) if m.manual => {
                adopt(conn, m).await?;
                cx.note(format!("~ {line}: adopted"));
            }
            // New, or over a mapped-only row (not a manual member yet).
            _ => {
                insert_member(conn, tenant_id, group.id, user.id, true).await?;
                let details = json!({ "user_id": user.id });
                cx.record(
                    conn,
                    format!("+ {line}"),
                    EventType::GroupMemberAdd,
                    target,
                    details,
                )
                .await?;
            }
        }
    }
    for m in existing
        .iter()
        .filter(|m| m.managed && !wanted.iter().any(|u| u.id == m.user_id))
    {
        // Someone else (the management API) removed it meanwhile: nothing
        // to report or audit.
        if !release(conn, m).await? {
            continue;
        }
        let email = users::Entity::find_by_id(m.user_id)
            .one(conn)
            .await?
            .map_or_else(|| m.user_id.to_string(), |u| u.email);
        let line = format!("- member {email} of {}", group.display_name);
        let details = json!({ "user_id": m.user_id });
        cx.record(conn, line, EventType::GroupMemberRemove, target, details)
            .await?;
    }
    Ok(())
}

async fn adopt(conn: &impl ConnectionTrait, m: &group_members::Model) -> anyhow::Result<()> {
    group_members::Entity::update_many()
        .col_expr(group_members::Column::Manual, true.into())
        .col_expr(group_members::Column::Managed, true.into())
        .filter(group_members::Column::GroupId.eq(m.group_id))
        .filter(group_members::Column::UserId.eq(m.user_id))
        .exec(conn)
        .await
        .context("adopting group membership")?;
    Ok(())
}

/// Ends apply's hold on a membership the file no longer lists: a row only
/// apply keeps is deleted, one an IdP mapping also keeps stays as the
/// mapping's. Neither write trusts the `idp_id` read earlier: each re-checks
/// it, and READ COMMITTED re-evaluates that on a row a concurrent sign-in
/// changed, so a mapped membership is never deleted and no row is left
/// without a source (`group_members_source_check`). Returns whether a row
/// changed (`false`: it is gone, removed concurrently).
async fn release(conn: &impl ConnectionTrait, m: &group_members::Model) -> anyhow::Result<bool> {
    let deleted = group_members::Entity::delete_many()
        .filter(group_members::Column::GroupId.eq(m.group_id))
        .filter(group_members::Column::UserId.eq(m.user_id))
        .filter(group_members::Column::IdpId.is_null())
        .exec(conn)
        .await
        .context("removing group membership")?;
    if deleted.rows_affected > 0 {
        return Ok(true);
    }
    let handed = group_members::Entity::update_many()
        .col_expr(group_members::Column::Manual, false.into())
        .col_expr(group_members::Column::Managed, false.into())
        .filter(group_members::Column::GroupId.eq(m.group_id))
        .filter(group_members::Column::UserId.eq(m.user_id))
        .filter(group_members::Column::IdpId.is_not_null())
        .exec(conn)
        .await
        .context("handing group membership to its mapping")?;
    Ok(handed.rows_affected > 0)
}

/// Deletes managed groups the file no longer declares.
pub async fn prune(conn: &impl ConnectionTrait, cx: &mut Ctx) -> anyhow::Result<()> {
    let managed = groups::Entity::find()
        .filter(groups::Column::TenantId.eq(cx.tenant_id))
        .filter(groups::Column::Managed.eq(true))
        .all(conn)
        .await?;
    let stale: Vec<_> = managed
        .into_iter()
        .filter(|g| !cx.kept.contains(&g.id))
        .collect();
    for group in stale {
        groups::Entity::delete_by_id(group.id).exec(conn).await?;
        let line = format!("- group {}", group.display_name);
        let details = json!({ "display_name": group.display_name });
        let target = Some(Target::Group(group.id));
        cx.record(conn, line, EventType::GroupDelete, target, details)
            .await?;
    }
    Ok(())
}
