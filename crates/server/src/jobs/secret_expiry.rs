//! Client secret expiry warning: [`WARN_BEFORE`] before a secret expires,
//! every verified, enabled GlobalAdmin and ApplicationAdmin of its tenant
//! (the directory roles that can add a new secret) gets one email. The
//! secret's `expiry_notified_at` is set in the same transaction as the
//! queued messages, so each secret is warned about once; a secret created
//! inside the window is warned about on the next run. Secrets of a disabled
//! tenant, or of one without such an admin, stay pending (and out of the
//! batch) until someone can be warned, so the marker never records a
//! warning nobody got. Only runs with email
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
    QuerySelect, TransactionTrait,
    sea_query::{Expr, ExprTrait, Query, SelectStatement},
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
        .filter(client_secrets::Column::TenantId.in_subquery(tenants_with_recipients()))
        .order_by_asc(client_secrets::Column::ExpiresAt)
        .limit(BATCH)
        .all(&txn)
        .await
        .context("loading expiring secrets")?;
    let mut recipients: HashMap<Uuid, (tenants::Model, Vec<users::Model>)> = HashMap::new();
    let mut warned = 0;
    for secret in &due {
        let (tenant, admins) = match recipients.entry(secret.tenant_id) {
            Entry::Occupied(known) => known.into_mut(),
            Entry::Vacant(new) => new.insert(load_recipients(&txn, secret.tenant_id).await?),
        };
        if warn(&txn, config, tenant, admins, secret).await? == 0 {
            continue;
        }
        warned += 1;
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
    if warned > 0 {
        tracing::info!(secrets = warned, "queued client secret expiry warnings");
    }
    Ok(Some(warned))
}

/// Enabled tenants with at least one admin [`load_recipients`] would warn.
fn tenants_with_recipients() -> SelectStatement {
    use directory_role_assignments as dra;
    Query::select()
        .distinct()
        .column((dra::Entity, dra::Column::TenantId))
        .from(dra::Entity)
        .inner_join(
            users::Entity,
            Expr::col((users::Entity, users::Column::TenantId))
                .equals((dra::Entity, dra::Column::TenantId))
                .and(
                    Expr::col((users::Entity, users::Column::Id))
                        .equals((dra::Entity, dra::Column::UserId)),
                ),
        )
        .inner_join(
            tenants::Entity,
            Expr::col((tenants::Entity, tenants::Column::Id))
                .equals((dra::Entity, dra::Column::TenantId)),
        )
        .and_where(dra::Column::Role.is_in(RECIPIENT_ROLES))
        .and_where(Expr::col((users::Entity, users::Column::Disabled)).eq(false))
        .and_where(Expr::col((users::Entity, users::Column::EmailVerified)).eq(true))
        .and_where(Expr::col((tenants::Entity, tenants::Column::Disabled)).eq(false))
        .to_owned()
}

/// The tenant and its admins who can replace a secret (none for a
/// disabled tenant: nobody can act on it). Keep in step with
/// [`tenants_with_recipients`].
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
) -> anyhow::Result<usize> {
    if admins.is_empty() {
        return Ok(0);
    }
    let Some(expires_at) = secret.expires_at else {
        return Ok(0);
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
    Ok(admins.len())
}

#[cfg(test)]
mod tests {
    use sea_orm::sea_query::PostgresQueryBuilder;

    use super::*;

    #[test]
    fn eligible_tenants_mirror_the_recipient_rules() {
        let sql = tenants_with_recipients().to_string(PostgresQueryBuilder);
        for part in [
            r#""users"."tenant_id" = "directory_role_assignments"."tenant_id""#,
            r#""users"."id" = "directory_role_assignments"."user_id""#,
            r#""role" IN ('GlobalAdmin', 'ApplicationAdmin')"#,
            r#""users"."disabled" = FALSE"#,
            r#""users"."email_verified" = TRUE"#,
            r#""tenants"."disabled" = FALSE"#,
        ] {
            assert!(sql.contains(part), "{part} missing from {sql}");
        }
    }
}
