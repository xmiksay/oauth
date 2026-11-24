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
use entity::applications;
use sea_orm::{ConnectionTrait, Statement};
use uuid::Uuid;

use super::{
    ctx::Ctx,
    spec::{AppSpec, ConsentSpec},
};

/// Locks `FOR UPDATE`, in id order, the grants of the tenant apply may
/// write, and records their ids in `cx.locked_grants`:
/// - every grant of a declared app the file removes a managed scope of
///   (all of them, not only those holding the value: a sign-in could add it
///   to another one while apply runs);
/// - every grant of an app apply deletes (`deleted`, cascades);
/// - every admin grant that is managed (pruned) or of a pair `consents`
///   declares (adopted, widened or narrowed).
///
/// Token requests for these grants wait for apply to commit, dry runs
/// included; other grants stay free.
pub async fn lock(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    apps: &[AppSpec],
    consents: &[ConsentSpec],
    deleted: &[applications::Model],
) -> anyhow::Result<()> {
    let losing = losing_scopes(conn, cx, apps).await?;
    let deleted: Vec<Uuid> = deleted.iter().map(|a| a.id).collect();
    let clients: Vec<String> = consents.iter().map(|c| c.client.clone()).collect();
    let resources: Vec<String> = consents.iter().map(|c| c.resource.clone()).collect();
    let rows = conn
        .query_all_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            "SELECT g.id FROM consent_grants g \
             WHERE g.tenant_id = $1 AND ( \
               g.resource_application_id = ANY($2) \
               OR g.resource_application_id = ANY($3) OR g.client_application_id = ANY($3) \
               OR (g.user_id IS NULL AND (g.managed OR EXISTS ( \
                 SELECT 1 FROM unnest($4::text[], $5::text[]) AS p(client, resource) \
                 JOIN applications c ON c.tenant_id = g.tenant_id \
                   AND c.id = g.client_application_id AND c.client_id = p.client \
                 JOIN applications r ON r.tenant_id = g.tenant_id \
                   AND r.id = g.resource_application_id AND r.client_id = p.resource)))) \
             ORDER BY g.id FOR UPDATE OF g",
            [
                cx.tenant_id.into(),
                losing.into(),
                deleted.into(),
                clients.into(),
                resources.into(),
            ],
        ))
        .await
        .context("locking consent grants")?;
    for row in rows {
        let id: Uuid = row.try_get("", "id").context("reading consent grant id")?;
        cx.locked_grants.insert(id);
    }
    Ok(())
}

/// The locked, declared apps the file removes a managed scope of. Their
/// scopes can't change under apply: it holds the apps (`apps::lock`).
async fn losing_scopes(
    conn: &impl ConnectionTrait,
    cx: &Ctx,
    apps: &[AppSpec],
) -> anyhow::Result<Vec<Uuid>> {
    let locked: Vec<Uuid> = cx.locked_apps.iter().copied().collect();
    let rows = conn
        .query_all_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            "SELECT s.application_id, a.client_id, s.value FROM app_scopes s \
             JOIN applications a ON a.tenant_id = s.tenant_id AND a.id = s.application_id \
             WHERE s.tenant_id = $1 AND s.managed AND s.application_id = ANY($2)",
            [cx.tenant_id.into(), locked.into()],
        ))
        .await
        .context("reading managed scopes")?;
    let scopes = rows
        .iter()
        .map(|r| {
            Ok((
                r.try_get::<Uuid>("", "application_id")?,
                r.try_get::<String>("", "client_id")?,
                r.try_get::<String>("", "value")?,
            ))
        })
        .collect::<Result<Vec<_>, sea_orm::DbErr>>()
        .context("reading managed scopes")?;
    Ok(removed_from(&scopes, apps))
}

/// Of `(app id, client_id, value)` managed scopes, the apps whose declared
/// scopes no longer list one of theirs. Undeclared apps are deleted, not
/// trimmed.
fn removed_from(scopes: &[(Uuid, String, String)], apps: &[AppSpec]) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = scopes
        .iter()
        .filter(|(_, client_id, value)| {
            apps.iter()
                .find(|s| &s.client_id == client_id)
                .is_some_and(|s| !s.scopes.iter().any(|w| &w.value == value))
        })
        .map(|(id, _, _)| *id)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Refuses grants apply wrote but [`lock`] didn't lock (the management API
/// or a sign-in created them while apply ran): they weren't taken in id
/// order with the others. Apply stops instead of committing.
pub fn ensure_locked(locked: &HashSet<Uuid>, ids: &[Uuid]) -> anyhow::Result<()> {
    if ids.iter().any(|id| !locked.contains(id)) {
        bail!("a consent grant was created while apply ran; run apply again");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provision::parse;

    #[test]
    fn only_locked_grants_may_be_written() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let locked = HashSet::from([a]);
        assert!(ensure_locked(&locked, &[]).is_ok());
        assert!(ensure_locked(&locked, &[a]).is_ok());
        assert!(ensure_locked(&locked, &[a, b]).is_err());
    }

    #[test]
    fn only_declared_apps_dropping_a_managed_scope_lose_scopes() {
        let spec = parse(
            "tenant: t
applications:
  - { client_id: kept, display_name: K, scopes: [{ value: a }, { value: b }] }
  - { client_id: trimmed, display_name: T, scopes: [{ value: a }] }
",
        )
        .unwrap();
        let (kept, trimmed, gone) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let row = |id: Uuid, client: &str, value: &str| (id, client.to_owned(), value.to_owned());
        let scopes = [
            row(kept, "kept", "a"),
            row(kept, "kept", "b"),
            row(trimmed, "trimmed", "a"),
            row(trimmed, "trimmed", "b"),
            row(trimmed, "trimmed", "c"),
            row(gone, "gone", "a"),
        ];
        assert_eq!(removed_from(&scopes, &spec.applications), vec![trimmed]);
        assert!(removed_from(&[], &spec.applications).is_empty());
    }
}
