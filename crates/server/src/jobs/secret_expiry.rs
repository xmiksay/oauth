//! Client secret expiry warning: [`WARN_BEFORE`] before a secret expires,
//! every verified, enabled GlobalAdmin and ApplicationAdmin of its tenant
//! (the directory roles that can add a new secret) gets one email. The
//! secret's `expiry_notified_at` is set in the same transaction as the
//! queued messages, so each secret is warned about once; a secret created
//! inside the window is warned about on the next run. Only runs with email
//! configured (a later SMTP setup still warns about pending secrets).
//!
//! Runs on an explicit `now` so tests can move the clock.

use std::collections::{HashMap, hash_map::Entry};

use anyhow::Context;
use chrono::{DateTime, Duration, FixedOffset, SecondsFormat};
use entity::{
    applications, client_secrets, directory_role_assignments,
    enums::{Channel, DirectoryRole},
    tenants, users,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, TransactionTrait, sea_query::Expr,
};
use uuid::Uuid;

use super::{SECRET_EXPIRY_LOCK_KEY, try_lock};
use crate::{
    config::Config,
    mail::{
        outbox::{self, NewMessage},
        templates::{self, Ctx, ExpiringSecret},
    },
};

pub const WARN_BEFORE: Duration = Duration::days(14);
/// Secrets handled per run; the rest wait for the next one.
const BATCH: u64 = 100;
/// An undelivered warning is stale after a few days.
const WARNING_TTL: Duration = Duration::days(3);
const RECIPIENT_ROLES: [DirectoryRole; 2] =
    [DirectoryRole::GlobalAdmin, DirectoryRole::ApplicationAdmin];

/// Secrets warned about; `None` if another replica holds the lock (or
/// email is off).
pub async fn run_once(
    db: &DatabaseConnection,
    config: &Config,
    now: DateTime<FixedOffset>,
) -> anyhow::Result<Option<usize>> {
    if !config.email_enabled() {
        return Ok(None);
    }
    let txn = db
        .begin()
        .await
        .context("starting secret expiry transaction")?;
    if !try_lock(&txn, SECRET_EXPIRY_LOCK_KEY).await? {
        return Ok(None);
    }
    let due = client_secrets::Entity::find()
        .filter(client_secrets::Column::ExpiryNotifiedAt.is_null())
        .filter(client_secrets::Column::ExpiresAt.gt(now))
        .filter(client_secrets::Column::ExpiresAt.lte(now + WARN_BEFORE))
        .order_by_asc(client_secrets::Column::ExpiresAt)
        .limit(BATCH)
        .all(&txn)
        .await
        .context("loading expiring secrets")?;
    let mut recipients: HashMap<Uuid, (tenants::Model, Vec<users::Model>)> = HashMap::new();
    for secret in &due {
        let (tenant, admins) = match recipients.entry(secret.tenant_id) {
            Entry::Occupied(known) => known.into_mut(),
            Entry::Vacant(new) => new.insert(load_recipients(&txn, secret.tenant_id).await?),
        };
        warn(&txn, config, tenant, admins, secret).await?;
        client_secrets::Entity::update_many()
            .col_expr(client_secrets::Column::ExpiryNotifiedAt, Expr::value(now))
            .filter(client_secrets::Column::Id.eq(secret.id))
            .exec(&txn)
            .await
            .context("marking secret warned")?;
    }
    txn.commit()
        .await
        .context("committing secret expiry warnings")?;
    if !due.is_empty() {
        tracing::info!(secrets = due.len(), "queued client secret expiry warnings");
    }
    Ok(Some(due.len()))
}

/// The tenant and its admins who can replace a secret (none for a
/// disabled tenant: nobody can act on it).
async fn load_recipients(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
) -> anyhow::Result<(tenants::Model, Vec<users::Model>)> {
    let tenant = tenants::Entity::find_by_id(tenant_id)
        .one(conn)
        .await
        .context("loading tenant")?
        .context("secret of a missing tenant")?;
    if tenant.disabled {
        return Ok((tenant, Vec::new()));
    }
    let ids: Vec<Uuid> = directory_role_assignments::Entity::find()
        .select_only()
        .column(directory_role_assignments::Column::UserId)
        .distinct()
        .filter(directory_role_assignments::Column::TenantId.eq(tenant_id))
        .filter(directory_role_assignments::Column::Role.is_in(RECIPIENT_ROLES))
        .into_tuple()
        .all(conn)
        .await
        .context("loading app administrators")?;
    let admins = users::Entity::find()
        .filter(users::Column::TenantId.eq(tenant_id))
        .filter(users::Column::Id.is_in(ids))
        .filter(users::Column::Disabled.eq(false))
        .filter(users::Column::EmailVerified.eq(true))
        .order_by_asc(users::Column::Id)
        .all(conn)
        .await
        .context("loading app administrator accounts")?;
    Ok((tenant, admins))
}

async fn warn(
    conn: &impl ConnectionTrait,
    config: &Config,
    tenant: &tenants::Model,
    admins: &[users::Model],
    secret: &client_secrets::Model,
) -> anyhow::Result<()> {
    if admins.is_empty() {
        return Ok(());
    }
    let Some(expires_at) = secret.expires_at else {
        return Ok(());
    };
    let app = applications::Entity::find()
        .filter(applications::Column::TenantId.eq(secret.tenant_id))
        .filter(applications::Column::Id.eq(secret.application_id))
        .one(conn)
        .await
        .context("loading secret's application")?
        .context("secret of a missing application")?;
    let manage_url = format!(
        "{}/admin/app-registrations/{}/secrets",
        config.tenant_origin(&tenant.slug),
        app.id
    );
    let expires = expires_at
        .to_utc()
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    let details = ExpiringSecret {
        app_name: &app.display_name,
        client_id: &app.client_id,
        hint: &secret.hint,
        description: secret.description.as_deref(),
        expires_at: &expires,
        manage_url: &manage_url,
    };
    for admin in admins {
        let ctx = Ctx {
            tenant_name: &tenant.display_name,
            user_name: &admin.display_name,
            user_email: &admin.email,
        };
        let rendered = templates::secret_expiring(&ctx, &details);
        outbox::enqueue(
            conn,
            &config.master_key,
            NewMessage {
                tenant_id: tenant.id,
                channel: Channel::Email,
                recipient: &admin.email,
                rendered: &rendered,
                ttl: WARNING_TTL,
            },
        )
        .await?;
    }
    Ok(())
}
