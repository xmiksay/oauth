//! The applications apply locks up front, in one id-ordered pass, before
//! its first app, consent or token write.

use std::collections::{BTreeSet, HashSet};

use anyhow::bail;
use entity::applications;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    sea_query::LockType,
};
use uuid::Uuid;

use super::{ctx::Ctx, spec::AppSpec};
use crate::api::app_rules::lock_app;

/// Locks, in id order and before apply writes to any app, consent or token,
/// every existing app the run will write or reference: the undeclared
/// managed apps it deletes (returned, for [`super::apps::prune`]) and
/// declared apps whose `identifier_uri` changes take `FOR UPDATE` (a
/// delete, a key column update); the other declared apps
/// `FOR NO KEY UPDATE` (`lock_app`); the apps the file only `referenced`
/// (`refs::undeclared`: required permissions, admin consents, role
/// assignments) `FOR KEY SHARE`, so a management API delete of one can't
/// cascade into a consent grant apply locks next and then make apply's FK
/// check wait for it. A token request locks its user, then its client and
/// resource apps `FOR KEY SHARE` in id order, then consent and token rows
/// (`backchannel::lock_apps`); locking them one at a time, between writes,
/// could deadlock with it. Records the ids of the apps it may write in
/// `cx.locked_apps`. Built-in apps can't be deleted, so they stay unlocked.
pub async fn lock(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    specs: &[AppSpec],
    referenced: &BTreeSet<&str>,
) -> anyhow::Result<Vec<applications::Model>> {
    let mut apps = applications::Entity::find()
        .filter(applications::Column::TenantId.eq(cx.tenant_id))
        .filter(applications::Column::Builtin.eq(false))
        .order_by_asc(applications::Column::Id)
        .all(conn)
        .await?;
    apps.retain(|a| {
        a.managed
            || referenced.contains(a.client_id.as_str())
            || specs.iter().any(|s| s.client_id == a.client_id)
    });
    let mut stale = Vec::new();
    for app in apps {
        let spec = specs.iter().find(|s| s.client_id == app.client_id);
        let declared = spec.map(|s| &s.identifier_uri);
        let lock = lock_type(app.managed, &app.identifier_uri, declared);
        let written = lock != LockType::KeyShare;
        let found = applications::Entity::find_by_id(app.id)
            .filter(applications::Column::TenantId.eq(cx.tenant_id))
            .lock(lock)
            .one(conn)
            .await?;
        let Some(found) = found else { continue };
        if !written {
            continue;
        }
        cx.locked_apps.insert(found.id);
        if spec.is_none() {
            stale.push(found);
        }
    }
    Ok(stale)
}

/// `declared`: the file's `identifier_uri` for the app (`None`: the app
/// isn't declared; `Some(None)`: declared without one, so it's kept). An
/// undeclared app is deleted when `managed`, else only referenced
/// (`refs::check` refused a reference to a managed one).
fn lock_type(
    managed: bool,
    stored: &Option<String>,
    declared: Option<&Option<Option<String>>>,
) -> LockType {
    match declared {
        None if managed => LockType::Update,
        None => LockType::KeyShare,
        Some(Some(uri)) if uri != stored => LockType::Update,
        Some(_) => LockType::NoKeyUpdate,
    }
}

/// Locks a declared app again (to read its current row). One the management
/// API created after [`lock`] ran would be locked only now, between apply's
/// app writes: out of id order, so it could deadlock with a token request
/// holding it while it waits for an app apply holds. Apply stops instead.
pub async fn relock(
    conn: &impl ConnectionTrait,
    cx: &Ctx,
    id: Uuid,
) -> anyhow::Result<applications::Model> {
    ensure_locked(&cx.locked_apps, id)?;
    Ok(lock_app(conn, cx.tenant_id, id).await?)
}

fn ensure_locked(locked: &HashSet<Uuid>, id: Uuid) -> anyhow::Result<()> {
    if !locked.contains(&id) {
        bail!("the application was created while apply ran; run apply again");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(stored: &Option<String>, declared: Option<&Option<Option<String>>>) -> LockType {
        lock_type(false, stored, declared)
    }

    #[test]
    fn deleted_apps_and_key_changes_take_the_strong_lock() {
        let uri = || Some("api://a".to_owned());
        assert_eq!(lock_type(true, &uri(), None), LockType::Update);
        assert_eq!(lock(&uri(), Some(&Some(None))), LockType::Update);
        let other = Some(Some("api://b".to_owned()));
        assert_eq!(lock(&uri(), Some(&other)), LockType::Update);
        assert_eq!(lock(&uri(), Some(&Some(uri()))), LockType::NoKeyUpdate);
        assert_eq!(lock(&uri(), Some(&None)), LockType::NoKeyUpdate);
        assert_eq!(lock(&None, Some(&Some(None))), LockType::NoKeyUpdate);
        assert_eq!(lock_type(true, &uri(), Some(&None)), LockType::NoKeyUpdate);
    }

    #[test]
    fn apps_only_referenced_take_the_weakest_lock() {
        assert_eq!(lock_type(false, &None, None), LockType::KeyShare);
        let uri = Some("api://a".to_owned());
        assert_eq!(lock_type(false, &uri, None), LockType::KeyShare);
    }

    #[test]
    fn only_apps_locked_up_front_may_be_locked_again() {
        let locked = Uuid::now_v7();
        let set = HashSet::from([locked]);
        assert!(ensure_locked(&set, locked).is_ok());
        let err = ensure_locked(&set, Uuid::now_v7()).unwrap_err();
        assert!(err.to_string().contains("run apply again"), "{err}");
    }
}
