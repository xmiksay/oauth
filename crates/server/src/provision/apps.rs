//! App registrations (by `client_id`) with their scopes and app roles,
//! validated by the management API's own rules (`api::app_body`, …).
//! Built-in apps can't be declared; secrets are never in the file.

use anyhow::{Context, bail};
use entity::{app_roles, app_scopes, applications, enums::ClientType};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
};
use serde_json::json;

use super::{
    ctx::{Ctx, diff, update_line},
    spec::{AppSpec, RoleSpec, ScopeSpec},
};
use crate::{
    api::{
        app_body::{apply as apply_body, parse},
        app_rules::lock_app,
        applications::{map_write_error, new_row},
        apps_roles::{NewRole, insert_role, member_types, update_role_fields},
        apps_scopes::{delete_scope, insert_scope, update_scope_fields},
        validate,
    },
    audit::{EventType, Target},
    config::Config,
    directory::display_name,
};

pub async fn apply(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    config: &Config,
    specs: &[AppSpec],
) -> anyhow::Result<()> {
    let loopback = config.idp_allow_http_loopback;
    for spec in specs {
        let what = || format!("application `{}`", spec.client_id);
        let app = upsert(conn, cx, spec, loopback).await.with_context(what)?;
        scopes(conn, cx, &app, &spec.scopes)
            .await
            .with_context(what)?;
        roles(conn, cx, &app, &spec.roles)
            .await
            .with_context(what)?;
    }
    Ok(())
}

async fn upsert(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    spec: &AppSpec,
    loopback: bool,
) -> anyhow::Result<applications::Model> {
    validate::client_id(&spec.client_id)?;
    let client_type: ClientType = match &spec.client_type {
        Some(raw) => parse(raw, "client_type", "confidential, public")?,
        None => ClientType::Confidential,
    };
    let body = spec.body();
    let found = applications::Entity::find()
        .filter(applications::Column::TenantId.eq(cx.tenant_id))
        .filter(applications::Column::ClientId.eq(&spec.client_id))
        .one(conn)
        .await?;
    let Some(found) = found else {
        let mut row = new_row(cx.tenant_id, &spec.client_id, client_type);
        apply_body(&mut row, &body, &spec.client_id, client_type, loopback)?;
        row.managed = Set(true);
        let app = applications::Entity::insert(row)
            .exec_with_returning(conn)
            .await
            .map_err(map_write_error)?;
        cx.kept.insert(app.id);
        let line = format!("+ application {}", app.client_id);
        let details = json!({ "client_id": app.client_id });
        let target = Some(Target::Application(app.id));
        cx.record(conn, line, EventType::ApplicationCreate, target, details)
            .await?;
        return Ok(app);
    };
    if found.builtin {
        bail!("built-in applications can't be declared");
    }
    let app = lock_app(conn, cx.tenant_id, found.id).await?;
    if spec.client_type.is_some() && client_type != app.client_type {
        bail!("client_type can't be changed");
    }
    cx.kept.insert(app.id);
    let mut row: applications::ActiveModel = app.clone().into();
    let fields = apply_body(&mut row, &body, &app.client_id, app.client_type, loopback)?;
    if fields.is_empty() && app.managed {
        return Ok(app);
    }
    row.managed = Set(true);
    if !fields.is_empty() {
        row.updated_at = Set(chrono::Utc::now().fixed_offset());
    }
    let updated = row.update(conn).await.map_err(map_write_error)?;
    let line = update_line(
        &format!("application {}", app.client_id),
        &diff(&app, &updated, &fields),
        !app.managed,
    );
    if fields.is_empty() {
        cx.note(line);
    } else {
        let details = json!({ "client_id": app.client_id, "fields": fields });
        let target = Some(Target::Application(app.id));
        cx.record(conn, line, EventType::ApplicationUpdate, target, details)
            .await?;
    }
    Ok(updated)
}

async fn scopes(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    app: &applications::Model,
    specs: &[ScopeSpec],
) -> anyhow::Result<()> {
    let existing = app_scopes::Entity::find()
        .filter(app_scopes::Column::ApplicationId.eq(app.id))
        .all(conn)
        .await?;
    let target = Some(Target::Application(app.id));
    // Removals first: they free room under the per-app cap.
    for scope in existing
        .iter()
        .filter(|s| s.managed && !specs.iter().any(|w| w.value == s.value))
    {
        delete_scope(conn, app, scope).await?;
        let line = format!("- scope {}/{}", app.client_id, scope.value);
        let details = json!({ "scope_id": scope.id, "value": scope.value });
        cx.record(
            conn,
            line,
            EventType::ApplicationScopeRemove,
            target,
            details,
        )
        .await?;
    }
    for spec in specs {
        validate::scope_value(&spec.value)?;
        let description = spec
            .description
            .as_deref()
            .map(validate::description)
            .transpose()?;
        let label = format!("scope {}/{}", app.client_id, spec.value);
        let Some(scope) = existing.iter().find(|s| s.value == spec.value) else {
            let admin = spec.admin_consent_required.unwrap_or(false);
            let value = spec.value.clone();
            let description = description.unwrap_or_default();
            let scope = insert_scope(conn, app, value, description, admin, true).await?;
            let details = json!({ "scope_id": scope.id, "value": scope.value });
            cx.record(
                conn,
                format!("+ {label}"),
                EventType::ApplicationScopeAdd,
                target,
                details,
            )
            .await?;
            continue;
        };
        let mut row: app_scopes::ActiveModel = scope.clone().into();
        let fields = update_scope_fields(&mut row, description, spec.admin_consent_required);
        if fields.is_empty() && scope.managed {
            continue;
        }
        row.managed = Set(true);
        let updated = row.update(conn).await?;
        let line = update_line(&label, &diff(scope, &updated, &fields), !scope.managed);
        if fields.is_empty() {
            cx.note(line);
        } else {
            let details = json!({ "scope_id": scope.id, "value": scope.value });
            cx.record(
                conn,
                line,
                EventType::ApplicationScopeUpdate,
                target,
                details,
            )
            .await?;
        }
    }
    Ok(())
}

async fn roles(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    app: &applications::Model,
    specs: &[RoleSpec],
) -> anyhow::Result<()> {
    let existing = app_roles::Entity::find()
        .filter(app_roles::Column::ApplicationId.eq(app.id))
        .all(conn)
        .await?;
    let target = Some(Target::Application(app.id));
    for role in existing
        .iter()
        .filter(|r| r.managed && !specs.iter().any(|w| w.value == r.value))
    {
        // Its assignments and required permissions cascade.
        app_roles::Entity::delete_by_id(role.id).exec(conn).await?;
        let line = format!("- role {}/{}", app.client_id, role.value);
        let details = json!({ "role_id": role.id, "value": role.value });
        cx.record(
            conn,
            line,
            EventType::ApplicationRoleRemove,
            target,
            details,
        )
        .await?;
    }
    for spec in specs {
        validate::permission_value(&spec.value, "role")?;
        let name = display_name(&spec.display_name, "role")?;
        let types = member_types(&spec.allowed_member_types)?;
        let description = spec
            .description
            .as_deref()
            .map(validate::description)
            .transpose()?;
        let label = format!("role {}/{}", app.client_id, spec.value);
        let Some(role) = existing.iter().find(|r| r.value == spec.value) else {
            let new = NewRole {
                value: spec.value.clone(),
                display_name: name,
                description: description.unwrap_or_default(),
                allowed_member_types: types,
            };
            let role = insert_role(conn, app, new, true).await?;
            let details = json!({ "role_id": role.id, "value": role.value });
            cx.record(
                conn,
                format!("+ {label}"),
                EventType::ApplicationRoleAdd,
                target,
                details,
            )
            .await?;
            continue;
        };
        let mut row: app_roles::ActiveModel = role.clone().into();
        let fields = update_role_fields(&mut row, Some(name), description, Some(types));
        if fields.is_empty() && role.managed {
            continue;
        }
        row.managed = Set(true);
        let updated = row.update(conn).await?;
        let line = update_line(&label, &diff(role, &updated, &fields), !role.managed);
        if fields.is_empty() {
            cx.note(line);
        } else {
            let details = json!({ "role_id": role.id, "value": role.value });
            cx.record(
                conn,
                line,
                EventType::ApplicationRoleUpdate,
                target,
                details,
            )
            .await?;
        }
    }
    Ok(())
}

/// Deletes managed apps the file no longer declares (everything hanging
/// off them cascades).
pub async fn prune(conn: &impl ConnectionTrait, cx: &mut Ctx) -> anyhow::Result<()> {
    let managed = applications::Entity::find()
        .filter(applications::Column::TenantId.eq(cx.tenant_id))
        .filter(applications::Column::Managed.eq(true))
        .filter(applications::Column::Builtin.eq(false))
        .all(conn)
        .await?;
    let stale: Vec<_> = managed
        .into_iter()
        .filter(|a| !cx.kept.contains(&a.id))
        .collect();
    for app in stale {
        applications::Entity::delete_by_id(app.id)
            .exec(conn)
            .await?;
        let line = format!("- application {}", app.client_id);
        let details = json!({ "client_id": app.client_id });
        let target = Some(Target::Application(app.id));
        cx.record(conn, line, EventType::ApplicationDelete, target, details)
            .await?;
    }
    Ok(())
}
