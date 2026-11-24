//! The consent grants apply may write, locked up front in one statement.
//!
//! A multi-resource refresh locks the user's grant and the admin grant of a
//! (client, resource) pair `FOR SHARE` in id order
//! (`consent::granted_scopes_for_share`). Apply writes consent rows in
//! several statements (one scope removal per scope, then admin consents),
//! so locking them as it goes would take them out of id order: holding a
//! user's grant while it waits for an older admin grant the refresh holds,
//! which waits for the user's grant. [`lock`] takes all of them first, in
//! id order; later writes only re-take locks apply already holds, and
//! [`ensure_locked`] refuses a grant created after [`lock`] ran.

use std::collections::HashSet;

use anyhow::{Context, bail};
use sea_orm::{ConnectionTrait, Statement};
use uuid::Uuid;

use super::ctx::Ctx;

/// Locks `FOR UPDATE`, in id order, every grant of the tenant whose resource
/// is an app [`super::apps::lock`] locked (scope removals rewrite these,
/// deleting apps cascades to them) and every admin grant of the tenant
/// (admin consents are narrowed, adopted and pruned). Apps apply creates
/// have no grants yet. Records the ids in `cx.locked_grants`.
pub async fn lock(conn: &impl ConnectionTrait, cx: &mut Ctx) -> anyhow::Result<()> {
    let apps: Vec<Uuid> = cx.locked_apps.iter().copied().collect();
    let rows = conn
        .query_all_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            "SELECT id FROM consent_grants \
             WHERE tenant_id = $1 AND (user_id IS NULL OR resource_application_id = ANY($2)) \
             ORDER BY id FOR UPDATE",
            [cx.tenant_id.into(), apps.into()],
        ))
        .await
        .context("locking consent grants")?;
    for row in rows {
        let id: Uuid = row.try_get("", "id").context("reading consent grant id")?;
        cx.locked_grants.insert(id);
    }
    Ok(())
}

/// Refuses to write grants [`lock`] didn't lock (the management API or a
/// sign-in created them while apply ran): locking one now would be out of
/// id order. Apply stops instead.
pub fn ensure_locked(locked: &HashSet<Uuid>, ids: &[Uuid]) -> anyhow::Result<()> {
    if ids.iter().any(|id| !locked.contains(id)) {
        bail!("a consent grant was created while apply ran; run apply again");
    }
    Ok(())
}

/// Before a scope removal rewrites the grants of `resource` holding
/// `value`: refuses if any of them isn't locked, so the rewrite (which
/// locks them again) never waits for a grant out of id order.
pub async fn ensure_scope_grants_locked(
    conn: &impl ConnectionTrait,
    cx: &Ctx,
    resource: Uuid,
    value: &str,
) -> anyhow::Result<()> {
    let rows = conn
        .query_all_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            "SELECT id FROM consent_grants \
             WHERE tenant_id = $1 AND resource_application_id = $2 AND $3 = ANY(scopes)",
            [cx.tenant_id.into(), resource.into(), value.into()],
        ))
        .await
        .context("reading consent grants")?;
    let ids = rows
        .iter()
        .map(|r| r.try_get::<Uuid>("", "id"))
        .collect::<Result<Vec<_>, _>>()
        .context("reading consent grant id")?;
    ensure_locked(&cx.locked_grants, &ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_locked_grants_may_be_written() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let locked = HashSet::from([a]);
        assert!(ensure_locked(&locked, &[]).is_ok());
        assert!(ensure_locked(&locked, &[a]).is_ok());
        assert!(ensure_locked(&locked, &[a, b]).is_err());
    }
}
