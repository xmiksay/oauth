//! Keeps the stored system tenant's slug in agreement with
//! `SYSTEM_TENANT_SLUG`. A different stored slug refuses startup unless
//! `SYSTEM_TENANT_RENAME=1`, which renames it (audited). Renaming moves the
//! tenant to another host, so its issuer changes: tokens and sessions it
//! issued stop working.

use anyhow::{Context, bail};
use entity::{enums::Outcome, tenants};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QuerySelect,
};
use serde_json::json;

use super::find_tenant_by_slug;
use crate::{
    audit::{self, Actor, Event, EventType, Target},
    config::Config,
};

/// What [`reconcile_slug`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum SlugOutcome {
    /// No system tenant yet (`oauth bootstrap` creates it with the
    /// configured slug) or it already has that slug.
    Unchanged,
    Renamed {
        from: String,
        to: String,
    },
}

/// Which command ran [`reconcile_slug`]; recorded as the audit event's
/// `details.via`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// `oauth serve` (`db::migrate_and_reconcile`).
    Startup,
    /// `oauth bootstrap`.
    Bootstrap,
}

impl Via {
    fn as_str(self) -> &'static str {
        match self {
            Via::Startup => "startup",
            Via::Bootstrap => "bootstrap",
        }
    }
}

/// Run on the startup (or bootstrap) transaction: refuses a stored system
/// tenant whose slug isn't the configured one, or renames it with
/// `SYSTEM_TENANT_RENAME=1` (refused when another tenant has the slug).
pub async fn reconcile_slug(
    conn: &impl ConnectionTrait,
    config: &Config,
    via: Via,
) -> anyhow::Result<SlugOutcome> {
    // Row lock: a concurrent bootstrap / replica waits and then sees the
    // renamed row instead of renaming (and auditing) it again.
    let Some(tenant) = tenants::Entity::find()
        .filter(tenants::Column::IsSystem.eq(true))
        .lock_exclusive()
        .one(conn)
        .await
        .context("locking the system tenant")?
    else {
        return Ok(SlugOutcome::Unchanged);
    };
    let wanted = config.system_tenant_slug.as_str();
    if tenant.slug == wanted {
        return Ok(SlugOutcome::Unchanged);
    }
    let from = tenant.slug.clone();
    if !config.system_tenant_rename {
        bail!(
            "the system tenant's slug is `{from}` but SYSTEM_TENANT_SLUG is `{wanted}`. \
             Set SYSTEM_TENANT_SLUG={from} to keep it, or start once with \
             SYSTEM_TENANT_RENAME=1 to rename it — that moves it to another host and \
             changes its issuer, so its tokens and sessions stop working"
        );
    }
    if find_tenant_by_slug(conn, wanted).await?.is_some() {
        bail!(
            "cannot rename the system tenant from `{from}` to `{wanted}`: \
             another tenant already has that slug"
        );
    }
    let id = tenant.id;
    let mut row: tenants::ActiveModel = tenant.into();
    row.slug = Set(wanted.to_owned());
    row.updated_at = Set(chrono::Utc::now().fixed_offset());
    row.update(conn)
        .await
        .context("renaming the system tenant")?;
    audit::record(
        conn,
        Event {
            tenant_id: id,
            actor: Actor::System,
            event_type: EventType::TenantRename,
            target: Some(Target::Tenant(id)),
            outcome: Outcome::Success,
            ip: None,
            details: json!({ "from": from, "to": wanted, "via": via.as_str() }),
        },
    )
    .await?;
    tracing::warn!(from = %from, to = %wanted, "renamed the system tenant");
    Ok(SlugOutcome::Renamed {
        from,
        to: wanted.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::Via;

    #[test]
    fn via_names_the_command() {
        assert_eq!(Via::Startup.as_str(), "startup");
        assert_eq!(Via::Bootstrap.as_str(), "bootstrap");
    }
}
