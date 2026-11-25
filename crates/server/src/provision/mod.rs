//! `oauth apply`: declarative provisioning of one tenant from a YAML file
//! ([`spec`], contract in `docs/provisioning.md`), with direct database
//! access like `oauth bootstrap`.
//!
//! Everything runs in ONE transaction holding a per-tenant advisory lock:
//! the file applies completely or not at all, and `--dry-run` runs the very
//! same steps and rolls back, so its diff is exactly what an apply would do.
//! Objects are matched by their natural keys (client_id, email, group name,
//! IdP name, scope / role value); a declared object that already exists is
//! updated and adopted (`managed = true`). Only managed objects the file no
//! longer declares are deleted. Validation reuses the management API's
//! rules; audit events carry actor type `apply`.

mod access;
mod app_locks;
mod apps;
mod consents;
mod ctx;
mod grant_locks;
mod groups;
mod idps;
mod refs;
pub mod spec;
mod users;

use anyhow::Context;
use sea_orm::{ConnectionTrait, DatabaseConnection, Statement, TransactionTrait};

use crate::{config::Config, db, directory};
pub use spec::{Spec, parse};

/// Looks up environment variables (`*_env` references): the process
/// environment in the CLI, a map in tests.
pub type Env<'a> = &'a (dyn Fn(&str) -> Option<String> + Sync);

pub struct Options {
    pub dry_run: bool,
}

#[derive(Debug)]
pub struct Report {
    pub tenant: String,
    pub dry_run: bool,
    /// `+` created, `~` updated, `-` deleted, in the order applied.
    pub changes: Vec<String>,
}

impl Report {
    pub fn render(&self) -> String {
        let mut out = self.changes.clone();
        let n = self.changes.len();
        out.push(match (self.dry_run, n) {
            (_, 0) => format!("Tenant `{}` is up to date.", self.tenant),
            (true, _) => format!(
                "Dry run: {n} change(s) to tenant `{}` (nothing was written).",
                self.tenant
            ),
            (false, _) => format!("Applied {n} change(s) to tenant `{}`.", self.tenant),
        });
        out.join("\n")
    }
}

/// Applies `spec` to its tenant. The schema must be migrated (`serve` and
/// `bootstrap` do that); anything pending is an error before any write.
pub async fn run(
    db: &DatabaseConnection,
    config: &Config,
    spec: &Spec,
    opts: &Options,
    env: Env<'_>,
) -> anyhow::Result<Report> {
    db::ensure_migrated(db).await?;
    let txn = db.begin().await.context("starting apply transaction")?;
    let tenant = directory::find_tenant_by_slug(&txn, &spec.tenant)
        .await?
        .with_context(|| {
            format!(
                "tenant `{}` not found (create it with `oauth bootstrap --tenant`)",
                spec.tenant
            )
        })?;
    // Concurrent applies of one tenant would each see the other's rows as
    // undeclared.
    txn.execute_raw(Statement::from_sql_and_values(
        txn.get_database_backend(),
        "SELECT pg_advisory_xact_lock(hashtextextended('apply:' || $1::text, 0))",
        [tenant.id.into()],
    ))
    .await
    .context("acquiring apply lock")?;
    // Before any user lock (IdP → user, like a federated sign-in).
    let locked_idps = idps::lock_all(&txn, tenant.id).await?;

    let mut cx = ctx::Ctx {
        tenant_id: tenant.id,
        changes: Vec::new(),
        kept: Default::default(),
        locked_idps,
        locked_apps: Default::default(),
        locked_grants: Default::default(),
        revocations: Vec::new(),
    };
    refs::check(&txn, &cx, spec).await?;
    let referenced = refs::undeclared(spec);
    // Creates and updates in dependency order, then deletions in reverse —
    // except for locks, which follow the global order IdP → user →
    // application → consent / session → tokens (`backchannel::lock_apps`):
    // every user lock (the existing users the file only references, `FOR
    // KEY SHARE`; directory roles; the users deleted at the end; then
    // disabling), then, in one id-ordered pass, every existing app it writes
    // (the apps deleted at the end included) or only references
    // (`FOR KEY SHARE`: `app_locks::lock`), before its first app, consent,
    // session or token write (disabling revokes sessions and tokens only
    // after locking every user it disables), then every consent grant it
    // may write, in one statement in id order (`grant_locks::lock`: a
    // multi-resource refresh locks its grants in id order), and every
    // consent write before the token revocations of scope and admin consent
    // removals (`ctx::Revocation`). A token request takes them in that order
    // too; the other way round, apply would hold one while waiting for a row
    // the request holds. The referenced users and apps are locked up front
    // because the later inserts pointing at them (required permissions,
    // consents, role assignments) take their FK `KEY SHARE` only then, after
    // the grant locks, while a management API delete locks the user or app
    // first and then cascades into those grants.
    users::lock_referenced(&txn, &cx, &referenced.users).await?;
    let disabled = users::apply(&txn, &mut cx, &spec.users, env).await?;
    groups::apply(&txn, &mut cx, &spec.groups).await?;
    idps::apply(&txn, &mut cx, config, &spec.identity_providers, env).await?;
    access::directory_roles(&txn, &mut cx, &spec.directory_roles).await?;
    let stale_users = users::lock_stale(&txn, &cx).await?;
    users::finish_disabling(&txn, &cx, &config.master_key, disabled).await?;
    let (apps, consents) = (&spec.applications, &spec.admin_consents);
    let stale_apps = app_locks::lock(&txn, &mut cx, apps, &referenced.apps).await?;
    grant_locks::lock(&txn, &mut cx, apps, consents, &stale_apps).await?;
    apps::apply(&txn, &mut cx, config, &spec.applications).await?;
    consents::required(&txn, &mut cx, &spec.applications).await?;
    let consented = consents::admin(&txn, &mut cx, &spec.admin_consents).await?;
    access::role_assignments(&txn, &mut cx, &spec.role_assignments, consented).await?;
    consents::prune(&txn, &mut cx).await?;
    // Only now, after the last consent write (consent → tokens).
    consents::revoke_tokens(&txn, &mut cx).await?;
    apps::prune(&txn, &mut cx, stale_apps).await?;
    idps::prune(&txn, &mut cx).await?;
    groups::prune(&txn, &mut cx).await?;
    users::prune(&txn, &mut cx, &config.master_key, stale_users).await?;

    if opts.dry_run {
        txn.rollback().await.context("rolling back dry run")?;
    } else {
        txn.commit().await.context("committing apply")?;
    }
    Ok(Report {
        tenant: tenant.slug,
        dry_run: opts.dry_run,
        changes: cx.changes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(dry_run: bool, changes: &[&str]) -> String {
        Report {
            tenant: "t".into(),
            dry_run,
            changes: changes.iter().map(|c| (*c).to_owned()).collect(),
        }
        .render()
    }

    #[test]
    fn reports_say_what_happened() {
        assert_eq!(report(false, &[]), "Tenant `t` is up to date.");
        assert!(report(true, &["+ group G"]).starts_with("+ group G\nDry run: 1 change(s)"));
        assert!(report(false, &["+ a", "- b"]).ends_with("Applied 2 change(s) to tenant `t`."));
    }
}
