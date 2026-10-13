//! Tenant creation: the tenant row, its signing keys and built-in apps are
//! committed together or not at all.

use anyhow::Context;
use entity::{
    enums::{KeyStatus, SigningAlg},
    tenants,
};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, TransactionSession,
    TransactionTrait,
};
use uuid::Uuid;

use super::{DirectoryError, builtin_apps, display_name, slug, violates_unique};
use crate::{config::Config, keys};

pub struct NewTenant<'a> {
    pub slug: &'a str,
    pub display_name: &'a str,
}

/// Creates a regular tenant. Reserved slugs (incl. `system`) are rejected.
pub async fn create_tenant(
    db: &impl TransactionTrait,
    config: &Config,
    new: NewTenant<'_>,
) -> Result<tenants::Model, DirectoryError> {
    slug::validate(new.slug)?;
    insert_provisioned(db, config, new, false).await
}

/// Creates the `system` tenant; only `oauth bootstrap` calls this.
pub(crate) async fn create_system_tenant(
    db: &impl TransactionTrait,
    config: &Config,
) -> Result<tenants::Model, DirectoryError> {
    let new = NewTenant {
        slug: slug::SYSTEM_TENANT_SLUG,
        display_name: "System",
    };
    // Format only: `system` is on the reserved list precisely so that nobody
    // but this path can take it.
    slug::validate_format(new.slug)?;
    insert_provisioned(db, config, new, true).await
}

/// Callers validate the slug first.
async fn insert_provisioned(
    db: &impl TransactionTrait,
    config: &Config,
    new: NewTenant<'_>,
    is_system: bool,
) -> Result<tenants::Model, DirectoryError> {
    let display_name = display_name(new.display_name, "tenant")?;
    // Generate before opening the (nested) transaction: RSA keygen is slow and
    // must not hold row locks or a pooled connection. Deliberate exception:
    // `oauth bootstrap` calls this inside its own transaction holding the
    // bootstrap advisory lock — acceptable for a one-shot CLI, and that lock
    // is exactly what serializes concurrent bootstraps.
    let rs256 = keys::generate(SigningAlg::Rs256).await?;
    let es256 = keys::generate(SigningAlg::Es256).await?;

    let txn = db.begin().await.context("starting tenant transaction")?;
    let row = tenants::ActiveModel {
        id: Set(Uuid::now_v7()),
        slug: Set(new.slug.to_owned()),
        display_name: Set(display_name),
        is_system: Set(is_system),
        disabled: Set(false),
        ..Default::default()
    };
    let tenant = tenants::Entity::insert(row)
        .exec_with_returning(&txn)
        .await
        .map_err(|err| {
            if violates_unique(&err, "tenants_slug_key") {
                DirectoryError::SlugTaken(new.slug.to_owned())
            } else {
                anyhow::Error::new(err).context("inserting tenant").into()
            }
        })?;
    for key in [&rs256, &es256] {
        keys::insert(&txn, &config.master_key, tenant.id, key, KeyStatus::Active).await?;
    }
    builtin_apps::provision(&txn, &config.public_url, &tenant).await?;
    txn.commit().await.context("committing tenant")?;
    tracing::info!(tenant = %tenant.slug, is_system, "tenant created");
    Ok(tenant)
}

pub async fn find_tenant_by_slug(
    conn: &impl ConnectionTrait,
    slug: &str,
) -> anyhow::Result<Option<tenants::Model>> {
    tenants::Entity::find()
        .filter(tenants::Column::Slug.eq(slug))
        .one(conn)
        .await
        .context("looking up tenant")
}

pub async fn find_system_tenant(
    conn: &impl ConnectionTrait,
) -> anyhow::Result<Option<tenants::Model>> {
    tenants::Entity::find()
        .filter(tenants::Column::IsSystem.eq(true))
        .one(conn)
        .await
        .context("looking up system tenant")
}
