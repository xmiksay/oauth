//! Updating an identity provider: one rule set shared by
//! `PATCH /api/v1/identity-providers/{id}` and `oauth apply`.

use std::net::IpAddr;

use entity::identity_providers;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectionTrait};
use serde_json::{Value, json};

use super::{
    guard::conflict_on_unique,
    identity_providers::ensure_same_kind,
    idp_body::{IdpBody, apply, ensure_domains_free, seal},
    idp_rules,
};
use crate::{
    audit::Actor,
    config::Config,
    error::{AppError, AppResult},
    federation::{group_map, identities, kinds},
};

/// Fields whose change points the provider somewhere else.
pub(crate) const REPOINT: [&str; 3] = ["issuer", "client_id", "discovery_url"];

/// A validated change of a locked provider, not yet written.
pub(crate) struct Prepared {
    pub row: identity_providers::ActiveModel,
    /// Changed fields (unchanged values sent back are ignored).
    pub fields: Vec<&'static str>,
    secret: Option<String>,
    repointed: bool,
    narrowed: bool,
}

/// Applies `body` to `idp` (locked by the caller, `api::identity_providers::lock`).
pub(crate) fn prepare(
    config: &Config,
    idp: &identity_providers::Model,
    body: &IdpBody,
) -> AppResult<Prepared> {
    ensure_same_kind(body, idp)?;
    let mut row: identity_providers::ActiveModel = idp.clone().into();
    let mut secret = None;
    let mut fields = apply(config, &mut row, body, &mut secret)?;
    let repointed = REPOINT.iter().any(|f| fields.contains(f));
    // A secret only ever goes to the provider it was entered for: pointing
    // the IdP elsewhere drops it unless a new one comes with the change.
    let moved = fields.contains(&"issuer") || fields.contains(&"discovery_url");
    if moved && secret.is_none() && idp.client_secret_sealed.is_some() {
        row.client_secret_sealed = Set(None);
        if !fields.contains(&"client_secret") {
            fields.push("client_secret");
        }
    }
    // Narrowing who may sign in must also fail a callback verified against
    // the wider list (it would still get mapped groups); no unlink needed,
    // but the mapped memberships go in `write`. Any change bumps (simplest);
    // only a real narrowing drops memberships.
    let admits = fields.contains(&"allowed_tenants") || fields.contains(&"hosted_domain");
    let narrowed = admits
        && idp_rules::Row::of(&row).is_none_or(|new| {
            let new = kinds::Rules {
                hosted_domain: new.hosted_domain,
                allowed_tenants: new.allowed_tenants,
                ..kinds::Rules::of(idp)
            };
            kinds::narrows(&kinds::Rules::of(idp), &new)
        });
    if repointed || admits {
        row.generation = Set(idp.generation.saturating_add(1));
    }
    Ok(Prepared {
        row,
        fields,
        secret,
        repointed,
        narrowed,
    })
}

/// Checks and stores a non-empty change; returns the updated row and the
/// `identity_provider.update` audit details (the caller records them).
pub(crate) async fn write(
    conn: &impl ConnectionTrait,
    config: &Config,
    idp: &identity_providers::Model,
    prepared: Prepared,
    actor: Actor,
    ip: Option<IpAddr>,
) -> AppResult<(identity_providers::Model, Value)> {
    let Prepared {
        mut row,
        fields,
        secret,
        repointed,
        narrowed,
    } = prepared;
    let (tenant_id, id) = (idp.tenant_id, idp.id);
    seal(config, &mut row, tenant_id, id, secret)?;
    idp_rules::check_secret(&row)?;
    if fields.contains(&"issuer") || fields.contains(&"allowed_tenants") {
        let stored = idp_rules::Row::of(&row).ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!("identity provider row incomplete"))
        })?;
        let mappings = group_map::count(conn, tenant_id, id).await?;
        idp_rules::check_mappings(&stored, mappings)?;
    }
    if fields.contains(&"email_domains") {
        let domains = row.email_domains.try_as_ref().cloned().unwrap_or_default();
        ensure_domains_free(conn, tenant_id, id, &domains).await?;
    }
    row.updated_at = Set(chrono::Utc::now().fixed_offset());
    let updated = row
        .update(conn)
        .await
        .map_err(|err| conflict_on_unique(err, "an identity provider with this name exists"))?;
    // Another issuer, client or discovery source means other subjects:
    // keeping the links would hand the old users' accounts to whoever the
    // new provider calls by those subjects.
    // Narrowing: identities don't record their upstream tenant / domain, so
    // every mapped membership goes; a de-listed user can't sign in to have
    // them re-synced, a still-allowed one gets them back on the next one.
    let (removed, memberships) = if repointed {
        identities::unlink_all(conn, tenant_id, id, actor, ip).await?
    } else if narrowed {
        let dropped = group_map::drop_owned(conn, tenant_id, id, None, None, actor, ip).await?;
        (0, dropped)
    } else {
        (0, 0)
    };
    let details = json!({
        "fields": fields,
        "identities_removed": removed,
        "memberships_removed": memberships,
    });
    Ok((updated, details))
}
