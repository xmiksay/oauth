//! Identity providers (by name). Apply never repoints one (issuer,
//! client_id, discovery_url: that unlinks every identity and must drop the
//! server's caches) and sets the client secret only while there is none.

use anyhow::{Context, bail};
use entity::identity_providers as idp;
use sea_orm::{
    ActiveEnum, ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait,
    QueryFilter,
};
use serde_json::json;
use uuid::Uuid;

use super::{
    Env,
    ctx::{Ctx, diff, update_line},
    spec::IdpSpec,
};
use crate::{
    api::{
        guard::conflict_on_unique,
        identity_providers::{create_kind, delete_locked, ensure_same_kind, lock, new_row},
        idp_body::{apply as apply_body, ensure_domains_free, seal},
        idp_rules::check_secret,
        idp_validate,
    },
    audit::{Actor, EventType, Target},
    config::Config,
};

const NAME_TAKEN: &str = "an identity provider with this name exists";
const REPOINT: [&str; 3] = ["issuer", "client_id", "discovery_url"];

pub async fn apply(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    config: &Config,
    specs: &[IdpSpec],
    env: Env<'_>,
) -> anyhow::Result<()> {
    for spec in specs {
        upsert(conn, cx, config, spec, env)
            .await
            .with_context(|| format!("identity provider `{}`", spec.name))?;
    }
    Ok(())
}

fn secret(spec: &IdpSpec, env: Env<'_>) -> anyhow::Result<Option<String>> {
    let Some(var) = &spec.client_secret_env else {
        return Ok(None);
    };
    env(var)
        .filter(|v| !v.is_empty())
        .map(Some)
        .with_context(|| format!("environment variable `{var}` (client secret) is not set"))
}

async fn upsert(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    config: &Config,
    spec: &IdpSpec,
    env: Env<'_>,
) -> anyhow::Result<()> {
    let tenant_id = cx.tenant_id;
    let name = idp_validate::name(&spec.name)?;
    let found = idp::Entity::find()
        .filter(idp::Column::TenantId.eq(tenant_id))
        .filter(idp::Column::Name.eq(&name))
        .one(conn)
        .await?;
    let Some(found) = found else {
        let body = spec.body(secret(spec, env)?);
        let id = Uuid::now_v7();
        let mut row = new_row(tenant_id, id, create_kind(&body)?);
        row.managed = Set(true);
        let mut plain = None;
        apply_body(config, &mut row, &body, &mut plain)?;
        seal(config, &mut row, tenant_id, id, plain)?;
        check_secret(&row)?;
        if let Set(domains) = &row.email_domains {
            ensure_domains_free(conn, tenant_id, id, domains).await?;
        }
        let created = idp::Entity::insert(row)
            .exec_with_returning(conn)
            .await
            .map_err(|err| conflict_on_unique(err, NAME_TAKEN))?;
        cx.kept.insert(id);
        let line = format!("+ identity provider {}", created.name);
        let details = json!({
            "name": created.name,
            "kind": created.kind.to_value(),
            "issuer": created.issuer,
            "policy": created.policy.to_value(),
        });
        let target = Some(Target::IdentityProvider(id));
        return cx
            .record(
                conn,
                line,
                EventType::IdentityProviderCreate,
                target,
                details,
            )
            .await;
    };
    let current = lock(conn, tenant_id, found.id).await?;
    cx.kept.insert(current.id);
    let new_secret = match current.client_secret_sealed {
        None => secret(spec, env)?,
        Some(_) => None,
    };
    let body = spec.body(new_secret);
    ensure_same_kind(&body, &current)?;
    let mut row: idp::ActiveModel = current.clone().into();
    let mut plain = None;
    let fields = apply_body(config, &mut row, &body, &mut plain)?;
    if let Some(field) = fields.iter().find(|f| REPOINT.contains(f)) {
        bail!(
            "changing `{field}` repoints the provider (every linked identity is removed); \
             apply doesn't do that: change it through the management API or admin UI"
        );
    }
    if fields.is_empty() && current.managed {
        return Ok(());
    }
    seal(config, &mut row, tenant_id, current.id, plain)?;
    check_secret(&row)?;
    if fields.contains(&"email_domains") {
        let domains = row.email_domains.try_as_ref().cloned().unwrap_or_default();
        ensure_domains_free(conn, tenant_id, current.id, &domains).await?;
    }
    row.managed = Set(true);
    if !fields.is_empty() {
        row.updated_at = Set(chrono::Utc::now().fixed_offset());
    }
    let updated = row
        .update(conn)
        .await
        .map_err(|err| conflict_on_unique(err, NAME_TAKEN))?;
    let line = update_line(
        &format!("identity provider {}", current.name),
        &diff(&current, &updated, &fields),
        !current.managed,
    );
    if fields.is_empty() {
        cx.note(line);
        return Ok(());
    }
    let details = json!({ "fields": fields, "identities_removed": 0, "memberships_removed": 0 });
    let target = Some(Target::IdentityProvider(current.id));
    cx.record(
        conn,
        line,
        EventType::IdentityProviderUpdate,
        target,
        details,
    )
    .await
}

/// Deletes managed providers the file no longer declares (with their
/// linked identities and mapped memberships, like the API).
pub async fn prune(conn: &impl ConnectionTrait, cx: &mut Ctx) -> anyhow::Result<()> {
    let managed = idp::Entity::find()
        .filter(idp::Column::TenantId.eq(cx.tenant_id))
        .filter(idp::Column::Managed.eq(true))
        .all(conn)
        .await?;
    let stale: Vec<_> = managed
        .into_iter()
        .filter(|i| !cx.kept.contains(&i.id))
        .collect();
    for found in stale {
        let current = lock(conn, cx.tenant_id, found.id).await?;
        let details = delete_locked(conn, &current, Actor::Apply, None).await?;
        let line = format!("- identity provider {}", current.name);
        let target = Some(Target::IdentityProvider(current.id));
        cx.record(
            conn,
            line,
            EventType::IdentityProviderDelete,
            target,
            details,
        )
        .await?;
    }
    Ok(())
}
