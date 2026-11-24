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
mod apps;
mod consents;
mod ctx;
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
    idps::lock_all(&txn, tenant.id).await?;

    let mut cx = ctx::Ctx {
        tenant_id: tenant.id,
        changes: Vec::new(),
        kept: Default::default(),
    };
    refs::check(&txn, &cx, spec).await?;
    // Creates and updates in dependency order, then deletions in reverse.
    let disabled = users::apply(&txn, &mut cx, &spec.users, env).await?;
    groups::apply(&txn, &mut cx, &spec.groups).await?;
    idps::apply(&txn, &mut cx, config, &spec.identity_providers, env).await?;
    apps::apply(&txn, &mut cx, config, &spec.applications).await?;
    consents::required(&txn, &mut cx, &spec.applications).await?;
    access::directory_roles(&txn, &mut cx, &spec.directory_roles).await?;
    users::finish_disabling(&txn, &cx, &config.master_key, disabled).await?;
    let consented = consents::admin(&txn, &mut cx, &spec.admin_consents).await?;
    access::role_assignments(&txn, &mut cx, &spec.role_assignments, consented).await?;
    consents::prune(&txn, &mut cx).await?;
    apps::prune(&txn, &mut cx).await?;
    idps::prune(&txn, &mut cx).await?;
    groups::prune(&txn, &mut cx).await?;
    users::prune(&txn, &mut cx, &config.master_key).await?;

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
