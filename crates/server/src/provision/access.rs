//! Directory roles of users and app role assignments (users, groups, client
//! apps — including the app roles of admin consents).

use anyhow::Context;
use entity::{
    app_role_assignments as ara, app_roles, applications, directory_role_assignments as dra,
    enums::DirectoryRole, groups, users,
};
use sea_orm::{
    ActiveEnum, ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait,
    QueryFilter,
};
use serde_json::json;
use uuid::Uuid;

use super::{
    ctx::{Ctx, update_line},
    spec::{DirectoryRoleSpec, RoleAssignmentSpec},
};
use crate::{
    api::{
        directory_roles::parse_role,
        guard::{conflict_on_unique, ensure_not_last_global_admin, lock_user},
        role_assignments::{self, Principal},
    },
    audit::{EventType, Target},
};

pub async fn directory_roles(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    specs: &[DirectoryRoleSpec],
) -> anyhow::Result<()> {
    let tenant_id = cx.tenant_id;
    let existing = dra::Entity::find()
        .filter(dra::Column::TenantId.eq(tenant_id))
        .all(conn)
        .await?;
    for spec in specs {
        let what = || format!("directory role `{}` of `{}`", spec.role, spec.user);
        let user = cx.user(conn, &spec.user).await.with_context(what)?;
        let role = parse_role(&spec.role).with_context(what)?;
        let label = format!("directory role {} of {}", role.to_value(), user.email);
        if let Some(a) = existing
            .iter()
            .find(|a| a.user_id == user.id && a.role == role)
        {
            cx.kept.insert(a.id);
            if !a.managed {
                let mut row: dra::ActiveModel = a.clone().into();
                row.managed = Set(true);
                row.update(conn).await?;
                cx.note(update_line(&label, &[], true));
            }
            continue;
        }
        lock_user(conn, tenant_id, user.id).await?;
        let row = dra::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(tenant_id),
            user_id: Set(user.id),
            role: Set(role),
            managed: Set(true),
            ..Default::default()
        };
        let a = dra::Entity::insert(row)
            .exec_with_returning(conn)
            .await
            .map_err(|err| conflict_on_unique(err, "the user already holds this role"))?;
        cx.kept.insert(a.id);
        let details = json!({ "role": role.to_value(), "assignment_id": a.id });
        let target = Some(Target::User(user.id));
        cx.record(
            conn,
            format!("+ {label}"),
            EventType::DirectoryRoleAssign,
            target,
            details,
        )
        .await?;
    }
    let stale: Vec<_> = existing
        .iter()
        .filter(|a| a.managed && !cx.kept.contains(&a.id))
        .collect();
    for a in stale {
        // User first, like the API's user writes and sign-in: a concurrent
        // login or role change then waits for this removal.
        let email = lock_user(conn, tenant_id, a.user_id).await?.email;
        if a.role == DirectoryRole::GlobalAdmin {
            ensure_not_last_global_admin(conn, tenant_id, a.user_id)
                .await
                .context("removing a Global Admin role")?;
        }
        dra::Entity::delete_by_id(a.id).exec(conn).await?;
        let line = format!("- directory role {} of {email}", a.role.to_value());
        let details = json!({ "role": a.role.to_value(), "assignment_id": a.id });
        let target = Some(Target::User(a.user_id));
        cx.record(
            conn,
            line,
            EventType::DirectoryRoleUnassign,
            target,
            details,
        )
        .await?;
    }
    Ok(())
}

struct Wanted {
    resource: applications::Model,
    role: app_roles::Model,
    principal: Principal,
    label: String,
}

async fn resolve(
    conn: &impl ConnectionTrait,
    cx: &Ctx,
    spec: &RoleAssignmentSpec,
) -> anyhow::Result<Wanted> {
    let resource = cx.app(conn, &spec.resource).await?;
    let role = find_role(conn, &resource, &spec.role).await?;
    let (principal, name) = match (&spec.user, &spec.group, &spec.application) {
        (Some(email), _, _) => (Principal::User(cx.user(conn, email).await?.id), email),
        (_, Some(group), _) => (Principal::Group(cx.group(conn, group).await?.id), group),
        (_, _, Some(client)) => (
            Principal::Application(cx.app(conn, client).await?.id),
            client,
        ),
        // `spec::check` guarantees exactly one.
        (None, None, None) => anyhow::bail!("the assignment names no principal"),
    };
    let label = format!(
        "role assignment {}/{} -> {} {name}",
        resource.client_id,
        role.value,
        kind(principal).0
    );
    Ok(Wanted {
        resource,
        role,
        principal,
        label,
    })
}

async fn find_role(
    conn: &impl ConnectionTrait,
    resource: &applications::Model,
    value: &str,
) -> anyhow::Result<app_roles::Model> {
    app_roles::Entity::find()
        .filter(app_roles::Column::ApplicationId.eq(resource.id))
        .filter(app_roles::Column::Value.eq(value))
        .one(conn)
        .await?
        .with_context(|| format!("`{}` has no app role `{value}`", resource.client_id))
}

pub async fn role_assignments(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    specs: &[RoleAssignmentSpec],
    from_consents: Vec<(app_roles::Model, applications::Model)>,
) -> anyhow::Result<()> {
    let mut wanted: Vec<Wanted> = Vec::new();
    for spec in specs {
        let w = resolve(conn, cx, spec).await.with_context(|| {
            format!("role assignment of `{}` on `{}`", spec.role, spec.resource)
        })?;
        wanted.push(w);
    }
    for (role, client) in from_consents {
        let resource = entity::applications::Entity::find_by_id(role.application_id)
            .one(conn)
            .await?
            .context("resource of a consented role")?;
        let label = format!(
            "role assignment {}/{} -> application {}",
            resource.client_id, role.value, client.client_id
        );
        wanted.push(Wanted {
            resource,
            role,
            principal: Principal::Application(client.id),
            label,
        });
    }
    let existing = ara::Entity::find()
        .filter(ara::Column::TenantId.eq(cx.tenant_id))
        .all(conn)
        .await?;
    let mut done: Vec<(Uuid, Principal)> = Vec::new();
    for w in wanted {
        if done.contains(&(w.role.id, w.principal)) {
            continue;
        }
        done.push((w.role.id, w.principal));
        let found = existing
            .iter()
            .find(|a| a.app_role_id == w.role.id && Principal::of(a) == Some(w.principal));
        if let Some(a) = found {
            cx.kept.insert(a.id);
            if !a.managed {
                set_managed(conn, a).await?;
                cx.note(update_line(&w.label, &[], true));
            }
            continue;
        }
        let a = role_assignments::insert(conn, cx.tenant_id, &w.role, w.principal)
            .await
            .with_context(|| w.label.clone())?;
        set_managed(conn, &a).await?;
        cx.kept.insert(a.id);
        let (kind, id) = kind(w.principal);
        let details = json!({
            "resource_client_id": w.resource.client_id,
            "role": w.role.value,
            "principal_type": kind,
            "principal_id": id,
        });
        let target = Some(Target::AppRoleAssignment(a.id));
        cx.record(
            conn,
            format!("+ {}", w.label),
            EventType::RoleAssignmentCreate,
            target,
            details,
        )
        .await?;
    }
    let stale: Vec<_> = existing
        .iter()
        .filter(|a| a.managed && !cx.kept.contains(&a.id))
        .collect();
    for a in stale {
        let (resource, line) = describe(conn, a).await?;
        ara::Entity::delete_by_id(a.id).exec(conn).await?;
        let details = json!({ "resource_client_id": resource, "app_role_id": a.app_role_id });
        let target = Some(Target::AppRoleAssignment(a.id));
        cx.record(conn, line, EventType::RoleAssignmentDelete, target, details)
            .await?;
    }
    Ok(())
}

/// The resource's client_id and the `- role assignment …` line of `a`,
/// named like the create lines (ids only for what is already gone).
async fn describe(conn: &impl ConnectionTrait, a: &ara::Model) -> anyhow::Result<(String, String)> {
    let resource = applications::Entity::find_by_id(a.resource_application_id)
        .one(conn)
        .await?
        .map_or_else(|| a.resource_application_id.to_string(), |r| r.client_id);
    let role = app_roles::Entity::find_by_id(a.app_role_id)
        .one(conn)
        .await?
        .map_or_else(|| a.app_role_id.to_string(), |r| r.value);
    let principal = match Principal::of(a) {
        Some(Principal::User(id)) => users::Entity::find_by_id(id)
            .one(conn)
            .await?
            .map_or_else(|| id.to_string(), |u| u.email),
        Some(Principal::Group(id)) => groups::Entity::find_by_id(id)
            .one(conn)
            .await?
            .map_or_else(|| id.to_string(), |g| g.display_name),
        Some(Principal::Application(id)) => applications::Entity::find_by_id(id)
            .one(conn)
            .await?
            .map_or_else(|| id.to_string(), |c| c.client_id),
        None => "?".to_owned(),
    };
    let kind = Principal::of(a).map_or("principal", |p| kind(p).0);
    let line = format!("- role assignment {resource}/{role} -> {kind} {principal}");
    Ok((resource, line))
}

fn kind(principal: Principal) -> (&'static str, Uuid) {
    match principal {
        Principal::User(id) => ("user", id),
        Principal::Group(id) => ("group", id),
        Principal::Application(id) => ("application", id),
    }
}

async fn set_managed(conn: &impl ConnectionTrait, a: &ara::Model) -> anyhow::Result<()> {
    let mut row: ara::ActiveModel = a.clone().into();
    row.managed = Set(true);
    row.update(conn).await?;
    Ok(())
}
