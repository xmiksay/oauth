//! Identity providers (by name). Apply never repoints one (issuer,
//! client_id, discovery_url: that unlinks every identity and must drop the
//! server's caches) and sets the client secret only while there is none.

use std::collections::HashSet;

use anyhow::{Context, bail};
use entity::identity_providers as idp;
use sea_orm::{
    ActiveEnum, ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait,
    QueryFilter, QueryOrder, QuerySelect,
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
        identity_providers::{create_kind, delete_locked, lock, new_row},
        idp_body::{apply as apply_body, ensure_domains_free, seal},
        idp_rules::check_secret,
        idp_update::{self, REPOINT},
        idp_validate,
    },
    audit::{Actor, EventType, Target},
    config::Config,
};

const NAME_TAKEN: &str = "an identity provider with this name exists";

/// Locks every identity provider of the tenant `FOR UPDATE`, in id order,
/// before apply touches anything else. The global lock order is IdP → user:
/// a federated sign-in holds its IdP `FOR SHARE` while it locks the user and
/// writes mapped memberships, so apply (which locks users, changes and
/// prunes IdPs, and releases memberships mappings may share) takes the IdPs
/// first. All of them, not just declared or managed ones: a mapping of any
/// provider may write the memberships `groups` releases. Returns the ids it
/// locked.
pub async fn lock_all(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
) -> anyhow::Result<HashSet<Uuid>> {
    let ids = idp::Entity::find()
        .select_only()
        .column(idp::Column::Id)
        .filter(idp::Column::TenantId.eq(tenant_id))
        .order_by_asc(idp::Column::Id)
        .lock_exclusive()
        .into_tuple::<Uuid>()
        .all(conn)
        .await
        .context("locking identity providers")?;
    Ok(ids.into_iter().collect())
}

/// Locks a provider again (to read its current row). One created after
/// [`lock_all`] ran (through the management API) would be locked only now,
/// after apply locked users: the reverse of the IdP → user order, which
/// could deadlock with a sign-in through it. Apply stops instead.
async fn relock(conn: &impl ConnectionTrait, cx: &Ctx, id: Uuid) -> anyhow::Result<idp::Model> {
    if !cx.locked_idps.contains(&id) {
        bail!("the identity provider was created while apply ran; run apply again");
    }
    Ok(lock(conn, cx.tenant_id, id).await?)
}

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
    let current = relock(conn, cx, found.id).await?;
    cx.kept.insert(current.id);
    let new_secret = match current.client_secret_sealed {
        None => secret(spec, env)?,
        Some(_) => None,
    };
    let body = spec.body(new_secret);
    let mut prepared = idp_update::prepare(config, &current, &body)?;
    if let Some(field) = prepared.fields.iter().find(|f| REPOINT.contains(f)) {
        bail!(
            "changing `{field}` repoints the provider (every linked identity is removed); \
             apply doesn't do that: change it through the management API or admin UI"
        );
    }
    let label = format!("identity provider {}", current.name);
    if prepared.fields.is_empty() {
        if !current.managed {
            let mut row: idp::ActiveModel = current.clone().into();
            row.managed = Set(true);
            row.update(conn).await?;
            cx.note(update_line(&label, &[], true));
        }
        return Ok(());
    }
    prepared.row.managed = Set(true);
    let fields = prepared.fields.clone();
    let (updated, details) =
        idp_update::write(conn, config, &current, prepared, Actor::Apply, None).await?;
    let line = update_line(&label, &diff(&current, &updated, &fields), !current.managed);
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
        let current = relock(conn, cx, found.id).await?;
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
