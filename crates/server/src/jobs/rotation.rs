//! Signing key rotation per (tenant, alg):
//!
//! 1. `KEY_PREPUBLISH_HOURS` before the active key turns `KEY_ROTATION_DAYS`
//!    old, a `next` key is generated and published in JWKS (not signing).
//! 2. Once the next key has been published for `KEY_PREPUBLISH_HOURS`, the
//!    active key is retired and the next one activated — in that order, in
//!    one transaction, because the partial unique indexes allow one active
//!    key per (tenant, alg) at every statement.
//! 3. The retired key stays in JWKS until `expires_at` = retirement + the
//!    tenant's longest access-token TTL + 1 h, so every token it signed can
//!    still be verified.
//!
//! Runs on an explicit `now` so tests can move the clock.

use anyhow::Context;
use chrono::{DateTime, Duration, FixedOffset};
use entity::{
    applications,
    enums::{KeyStatus, SigningAlg},
    signing_keys, tenants,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect,
    TransactionTrait, sea_query::Expr,
};
use uuid::Uuid;

use super::{ROTATION_LOCK_KEY, try_lock};
use crate::{config::Config, keys, tokens::DEFAULT_TTL_SECS};

const ALGS: [SigningAlg; 2] = [SigningAlg::Rs256, SigningAlg::Es256];
const RETIREMENT_GRACE: Duration = Duration::hours(1);

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub published: usize,
    pub activated: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    None,
    PublishNext,
    Activate,
}

/// Pure decision for one (tenant, alg).
fn decide(
    active: Option<&signing_keys::Model>,
    next: Option<&signing_keys::Model>,
    config: &Config,
    now: DateTime<FixedOffset>,
) -> Action {
    let prepublish = Duration::hours(i64::from(config.key_prepublish_hours));
    let rotation = Duration::days(i64::from(config.key_rotation_days));
    match (active, next) {
        (_, Some(next)) if active.is_none() || next.created_at + prepublish <= now => {
            Action::Activate
        }
        (_, Some(_)) => Action::None,
        (None, None) => Action::PublishNext,
        (Some(active), None) => {
            let since = active.activated_at.unwrap_or(active.created_at);
            if since + rotation - prepublish <= now {
                Action::PublishNext
            } else {
                Action::None
            }
        }
    }
}

/// `None` if another replica holds the rotation lock.
pub async fn run_once(
    db: &DatabaseConnection,
    config: &Config,
    now: DateTime<FixedOffset>,
) -> anyhow::Result<Option<Report>> {
    // The lock transaction only holds the leader lock; each tenant rotates
    // in its own transaction so one failing tenant doesn't block the rest.
    let lock = db.begin().await.context("starting rotation transaction")?;
    if !try_lock(&lock, ROTATION_LOCK_KEY).await? {
        return Ok(None);
    }
    let tenant_ids: Vec<Uuid> = tenants::Entity::find()
        .select_only()
        .column(tenants::Column::Id)
        .into_tuple()
        .all(db)
        .await
        .context("listing tenants")?;
    let mut report = Report::default();
    for tenant_id in tenant_ids {
        match rotate_tenant(db, config, tenant_id, now).await {
            Ok(actions) => {
                for action in actions {
                    match action {
                        Action::PublishNext => report.published += 1,
                        Action::Activate => report.activated += 1,
                        Action::None => {}
                    }
                }
            }
            Err(err) => tracing::warn!(%tenant_id, error = ?err, "key rotation failed for tenant"),
        }
    }
    lock.commit().await.context("releasing rotation lock")?;
    if report != Report::default() {
        tracing::info!(?report, "signing keys rotated");
    }
    Ok(Some(report))
}

async fn rotate_tenant(
    db: &DatabaseConnection,
    config: &Config,
    tenant_id: Uuid,
    now: DateTime<FixedOffset>,
) -> anyhow::Result<Vec<Action>> {
    let txn = db.begin().await.context("starting tenant rotation")?;
    let mut actions = Vec::with_capacity(ALGS.len());
    for alg in ALGS {
        actions.push(rotate(&txn, config, tenant_id, alg, now).await?);
    }
    txn.commit().await.context("committing key rotation")?;
    Ok(actions)
}

async fn rotate(
    conn: &impl ConnectionTrait,
    config: &Config,
    tenant_id: Uuid,
    alg: SigningAlg,
    now: DateTime<FixedOffset>,
) -> anyhow::Result<Action> {
    let rows = signing_keys::Entity::find()
        .filter(signing_keys::Column::TenantId.eq(tenant_id))
        .filter(signing_keys::Column::Alg.eq(alg))
        .filter(signing_keys::Column::Status.is_in([KeyStatus::Active, KeyStatus::Next]))
        .all(conn)
        .await
        .context("loading signing keys")?;
    let active = rows.iter().find(|k| k.status == KeyStatus::Active);
    let next = rows.iter().find(|k| k.status == KeyStatus::Next);
    let action = decide(active, next, config, now);
    match (&action, next) {
        (Action::PublishNext, _) => {
            let key = keys::generate(alg).await?;
            // A tenant without any key (shouldn't happen) gets an active one.
            let status = if active.is_some() {
                KeyStatus::Next
            } else {
                KeyStatus::Active
            };
            keys::insert_at(conn, &config.master_key, tenant_id, &key, status, now).await?;
        }
        (Action::Activate, Some(next)) => {
            if let Some(active) = active {
                let expires_at = now + max_token_ttl(conn, tenant_id).await? + RETIREMENT_GRACE;
                set_status(conn, active.id, KeyStatus::Retired, now, Some(expires_at)).await?;
            }
            set_status(conn, next.id, KeyStatus::Active, now, None).await?;
        }
        _ => {}
    }
    Ok(action)
}

async fn set_status(
    conn: &impl ConnectionTrait,
    id: Uuid,
    status: KeyStatus,
    now: DateTime<FixedOffset>,
    expires_at: Option<DateTime<FixedOffset>>,
) -> anyhow::Result<()> {
    let column = match status {
        KeyStatus::Retired => signing_keys::Column::RetiredAt,
        KeyStatus::Active | KeyStatus::Next => signing_keys::Column::ActivatedAt,
    };
    signing_keys::Entity::update_many()
        .col_expr(signing_keys::Column::Status, Expr::value(status))
        .col_expr(column, Expr::value(now))
        .col_expr(signing_keys::Column::ExpiresAt, Expr::value(expires_at))
        .filter(signing_keys::Column::Id.eq(id))
        .exec(conn)
        .await
        .context("updating signing key status")?;
    Ok(())
}

/// Longest lifetime of anything this tenant's keys sign.
async fn max_token_ttl(conn: &impl ConnectionTrait, tenant_id: Uuid) -> anyhow::Result<Duration> {
    let max: Option<i32> = applications::Entity::find()
        .select_only()
        .column_as(applications::Column::AccessTokenTtlSecs.max(), "max")
        .filter(applications::Column::TenantId.eq(tenant_id))
        .into_tuple()
        .one(conn)
        .await
        .context("loading max access token TTL")?
        .flatten();
    let secs = i64::from(max.unwrap_or(0)).max(DEFAULT_TTL_SECS);
    Ok(Duration::seconds(secs))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config() -> Config {
        let env = HashMap::from([
            ("DATABASE_URL", "postgres://x".to_owned()),
            ("PUBLIC_URL", "https://id.example.com".to_owned()),
            (
                "OAUTH_MASTER_KEY",
                "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=".to_owned(),
            ),
        ]);
        Config::from_lookup(|k| env.get(k).cloned()).unwrap()
    }

    fn key(status: KeyStatus, created: DateTime<FixedOffset>) -> signing_keys::Model {
        signing_keys::Model {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            kid: "k".into(),
            alg: SigningAlg::Rs256,
            status,
            private_key_enc: vec![],
            public_jwk: serde_json::Value::Null,
            created_at: created,
            activated_at: (status == KeyStatus::Active).then_some(created),
            retired_at: None,
            expires_at: None,
        }
    }

    #[test]
    fn rotation_schedule() {
        let cfg = config(); // 90 days, 48 h prepublish
        let t0 = chrono::Utc::now().fixed_offset();
        let active = key(KeyStatus::Active, t0);
        assert_eq!(
            decide(Some(&active), None, &cfg, t0 + Duration::days(87)),
            Action::None
        );
        assert_eq!(
            decide(Some(&active), None, &cfg, t0 + Duration::days(88)),
            Action::PublishNext
        );
        let next = key(KeyStatus::Next, t0 + Duration::days(88));
        let at = |d: i64, h: i64| t0 + Duration::days(d) + Duration::hours(h);
        assert_eq!(
            decide(Some(&active), Some(&next), &cfg, at(89, 23)),
            Action::None
        );
        assert_eq!(
            decide(Some(&active), Some(&next), &cfg, at(90, 0)),
            Action::Activate
        );
        // Orphaned states heal themselves.
        assert_eq!(decide(None, Some(&next), &cfg, t0), Action::Activate);
        assert_eq!(decide(None, None, &cfg, t0), Action::PublishNext);
    }
}
