//! Required permissions of the declared apps and tenant-wide (admin)
//! consents to them. A consent's app roles become app role assignments of
//! the client (reconciled with the file's `role_assignments`).

use anyhow::{Context, bail};
use entity::{app_required_permissions as arp, app_roles, applications, consent_grants};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait,
    QueryFilter,
};
use serde_json::json;
use uuid::Uuid;

use super::{
    ctx::{Ctx, Revocation, diff, update_line},
    spec::{AppSpec, ConsentSpec, PermissionSpec},
};
use crate::{
    api::{
        app_rules::{MAX_REQUIRED_PERMISSIONS, ensure_below},
        apps_permissions::{APPLICATION, DELEGATED, lookup, resolved},
        consents::{pick, revoke_tokens_of},
        guard::conflict_on_unique,
    },
    audit::{EventType, Target},
    consent,
    tokens::refresh,
};

pub async fn required(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    specs: &[AppSpec],
) -> anyhow::Result<()> {
    for spec in specs {
        required_of(conn, cx, &spec.client_id, &spec.required_permissions)
            .await
            .with_context(|| format!("required permissions of `{}`", spec.client_id))?;
    }
    Ok(())
}

async fn required_of(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    client_id: &str,
    specs: &[PermissionSpec],
) -> anyhow::Result<()> {
    let app = cx.app(conn, client_id).await?;
    let mut wanted = Vec::new();
    for p in specs {
        let resource = cx.app(conn, &p.resource).await?;
        let (scope_id, role_id) = lookup(conn, resource.id, &p.kind, &p.value).await?;
        wanted.push((p, resource, scope_id, role_id));
    }
    let existing = resolved(conn, app.id, None).await?;
    let target = Some(Target::Application(app.id));
    let label = |res: &str, kind: &str, value: &str| {
        format!("required permission {client_id} -> {res} {kind} {value}")
    };
    for e in &existing {
        let row = &e.row;
        let keep = wanted.iter().any(|(_, r, s, o)| {
            r.id == row.resource_application_id && *s == row.scope_id && *o == row.app_role_id
        });
        if keep {
            if !row.managed {
                let mut active: arp::ActiveModel = row.clone().into();
                active.managed = Set(true);
                active.update(conn).await?;
                let what = label(&e.resource_client_id, e.kind, &e.value);
                cx.note(update_line(&what, &[], true));
            }
        } else if row.managed {
            arp::Entity::delete_by_id(row.id).exec(conn).await?;
            let line = format!("- {}", label(&e.resource_client_id, e.kind, &e.value));
            let details = json!({ "permission_id": row.id });
            cx.record(
                conn,
                line,
                EventType::ApplicationPermissionRemove,
                target,
                details,
            )
            .await?;
        }
    }
    for (p, resource, scope_id, role_id) in wanted {
        let present = existing.iter().any(|e| {
            e.row.resource_application_id == resource.id
                && e.row.scope_id == scope_id
                && e.row.app_role_id == role_id
        });
        if present {
            continue;
        }
        let count = arp::Entity::find()
            .filter(arp::Column::ApplicationId.eq(app.id))
            .count(conn)
            .await?;
        ensure_below(count, MAX_REQUIRED_PERMISSIONS, "required permissions")?;
        let row = arp::ActiveModel {
            id: Set(Uuid::now_v7()),
            tenant_id: Set(cx.tenant_id),
            application_id: Set(app.id),
            resource_application_id: Set(resource.id),
            scope_id: Set(scope_id),
            app_role_id: Set(role_id),
            managed: Set(true),
            ..Default::default()
        };
        let created = arp::Entity::insert(row)
            .exec_with_returning(conn)
            .await
            .map_err(|e| conflict_on_unique(e, "the app already requires this permission"))?;
        let line = format!("+ {}", label(&resource.client_id, &p.kind, &p.value));
        let details = json!({
            "permission_id": created.id,
            "resource_client_id": resource.client_id,
            "type": p.kind,
            "value": p.value,
        });
        cx.record(
            conn,
            line,
            EventType::ApplicationPermissionAdd,
            target,
            details,
        )
        .await?;
    }
    Ok(())
}

/// Reconciles the admin consent grants; returns the app roles the consents
/// assign, as `(role, client app)`.
pub async fn admin(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    specs: &[ConsentSpec],
) -> anyhow::Result<Vec<(app_roles::Model, applications::Model)>> {
    let mut roles = Vec::new();
    for spec in specs {
        let found = grant(conn, cx, spec).await.with_context(|| {
            format!("admin consent of `{}` to `{}`", spec.client, spec.resource)
        })?;
        roles.extend(found);
    }
    Ok(roles)
}

async fn grant(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    spec: &ConsentSpec,
) -> anyhow::Result<Vec<(app_roles::Model, applications::Model)>> {
    let client = cx.app(conn, &spec.client).await?;
    let resource = cx.app(conn, &spec.resource).await?;
    let required = resolved(conn, client.id, Some(resource.id)).await?;
    let of = |kind: &str| -> Vec<String> {
        let mut v: Vec<String> = required
            .iter()
            .filter(|p| p.kind == kind)
            .map(|p| p.value.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    // Same rules as `POST /consents`: nothing listed = everything required.
    let (scopes, role_values) = if spec.scopes.is_some() || spec.app_roles.is_some() {
        (
            pick(
                Some(spec.scopes.as_deref().unwrap_or_default()),
                &of(DELEGATED),
                "scope",
            )?,
            pick(
                Some(spec.app_roles.as_deref().unwrap_or_default()),
                &of(APPLICATION),
                "app role",
            )?,
        )
    } else {
        (of(DELEGATED), of(APPLICATION))
    };
    if scopes.is_empty() && role_values.is_empty() {
        bail!("nothing to grant: the client requires no permissions on this resource");
    }
    let mut roles = Vec::new();
    for value in &role_values {
        let role = app_roles::Entity::find()
            .filter(app_roles::Column::ApplicationId.eq(resource.id))
            .filter(app_roles::Column::Value.eq(value))
            .one(conn)
            .await?
            .with_context(|| format!("app role `{value}` not found"))?;
        roles.push((role, client.clone()));
    }
    let existing = consent_grants::Entity::find()
        .filter(consent_grants::Column::TenantId.eq(cx.tenant_id))
        .filter(consent_grants::Column::ClientApplicationId.eq(client.id))
        .filter(consent_grants::Column::ResourceApplicationId.eq(resource.id))
        .filter(consent_grants::Column::UserId.is_null())
        .one(conn)
        .await?;
    let label = format!(
        "admin consent {} -> {}",
        client.client_id, resource.client_id
    );
    let details = json!({
        "client_id": client.client_id,
        "resource_client_id": resource.client_id,
        "scopes": scopes,
        "app_roles": role_values,
    });
    if scopes.is_empty() {
        // A grant left over is pruned if managed, kept otherwise.
        return Ok(roles);
    }
    let Some(found) = existing else {
        insert(conn, cx, &client, &resource, &scopes, &label, details).await?;
        return Ok(roles);
    };
    let mut current = found.scopes.clone();
    current.sort();
    if current == scopes {
        cx.kept.insert(found.id);
        if !found.managed {
            mark(conn, found.id).await?;
            cx.note(update_line(&label, &[], true));
        }
    } else if current.iter().all(|s| scopes.contains(s)) {
        // Widening keeps the tokens already issued under the grant.
        cx.kept.insert(found.id);
        let mut row: consent_grants::ActiveModel = found.clone().into();
        row.scopes = Set(scopes.clone());
        row.managed = Set(true);
        row.updated_at = Set(chrono::Utc::now().fixed_offset());
        let updated = row.update(conn).await?;
        let line = update_line(&label, &diff(&found, &updated, &["scopes"]), !found.managed);
        let target = Some(Target::ConsentGrant(found.id));
        cx.record(conn, line, EventType::ConsentGrant, target, details)
            .await?;
    } else {
        // Narrowing: revoke like the API does (the tokens after the last
        // consent write), then grant the new set.
        delete_grant(conn, cx, &found).await?;
        let revoked = json!({ "scopes": found.scopes, "user_id": null });
        let target = Some(Target::ConsentGrant(found.id));
        cx.record(
            conn,
            format!("- {label}"),
            EventType::ConsentRevoke,
            target,
            revoked,
        )
        .await?;
        insert(conn, cx, &client, &resource, &scopes, &label, details).await?;
    }
    Ok(roles)
}

async fn insert(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    client: &applications::Model,
    resource: &applications::Model,
    scopes: &[String],
    label: &str,
    details: serde_json::Value,
) -> anyhow::Result<()> {
    let id = consent::store_grant(conn, cx.tenant_id, client.id, resource.id, None, scopes).await?;
    mark(conn, id).await?;
    cx.kept.insert(id);
    let line = format!("+ {label}: {}", scopes.join(" "));
    cx.record(
        conn,
        line,
        EventType::ConsentGrant,
        Some(Target::ConsentGrant(id)),
        details,
    )
    .await
}

async fn mark(conn: &impl ConnectionTrait, id: Uuid) -> anyhow::Result<()> {
    consent_grants::Entity::update_many()
        .col_expr(consent_grants::Column::Managed, true.into())
        .filter(consent_grants::Column::Id.eq(id))
        .exec(conn)
        .await
        .context("marking consent grant")?;
    Ok(())
}

/// Revokes managed admin consents the file no longer declares.
pub async fn prune(conn: &impl ConnectionTrait, cx: &mut Ctx) -> anyhow::Result<()> {
    let managed = consent_grants::Entity::find()
        .filter(consent_grants::Column::TenantId.eq(cx.tenant_id))
        .filter(consent_grants::Column::Managed.eq(true))
        .filter(consent_grants::Column::UserId.is_null())
        .all(conn)
        .await?;
    let stale: Vec<_> = managed
        .into_iter()
        .filter(|g| !cx.kept.contains(&g.id))
        .collect();
    for grant in stale {
        delete_grant(conn, cx, &grant).await?;
        let name = |id: Uuid| async move {
            applications::Entity::find_by_id(id)
                .one(conn)
                .await
                .map(|a| a.map_or_else(|| id.to_string(), |a| a.client_id))
        };
        let line = format!(
            "- admin consent {} -> {}",
            name(grant.client_application_id).await?,
            name(grant.resource_application_id).await?
        );
        let details = json!({ "scopes": grant.scopes, "user_id": null });
        let target = Some(Target::ConsentGrant(grant.id));
        cx.record(conn, line, EventType::ConsentRevoke, target, details)
            .await?;
    }
    Ok(())
}

/// Deletes `grant`, leaving its tokens to [`revoke_tokens`].
async fn delete_grant(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    grant: &consent_grants::Model,
) -> anyhow::Result<()> {
    consent_grants::Entity::delete_by_id(grant.id)
        .exec(conn)
        .await
        .context("deleting consent grant")?;
    cx.revocations.push(Revocation::Grant(grant.clone()));
    Ok(())
}

/// Revokes the tokens of the scopes and admin consents apply removed. Runs
/// after its last consent write, so it never holds a token row while it
/// waits for a consent row a multi-resource refresh holds.
pub async fn revoke_tokens(conn: &impl ConnectionTrait, cx: &mut Ctx) -> anyhow::Result<()> {
    for revocation in std::mem::take(&mut cx.revocations) {
        match revocation {
            Revocation::Scope { resource, value } => {
                refresh::revoke_by_scope(conn, cx.tenant_id, resource, &value).await?;
            }
            Revocation::Grant(grant) => revoke_tokens_of(conn, &grant).await?,
        }
    }
    Ok(())
}
