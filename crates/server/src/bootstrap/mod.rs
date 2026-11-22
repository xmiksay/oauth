//! `oauth bootstrap`: idempotently ensure a tenant (the system tenant,
//! `SYSTEM_TENANT_SLUG`, or a regular one with `--tenant`), a Global Admin in it and / or a provisioning app
//! ([`provisioning`]). Safe to re-run (e.g. from every deploy).

pub mod provisioning;

use anyhow::Context;
use entity::{enums::DirectoryRole, tenants, users};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, Statement, TransactionTrait,
};
use serde_json::json;
use zeroize::Zeroizing;

use crate::{
    audit::{self, Actor, EventType, Target},
    config::Config,
    db,
    directory::{self, NewTenant, NewUser, SlugOutcome, SlugVia, builtin_apps, password},
};

/// Serializes concurrent bootstraps ("oauthbst" in ASCII); distinct from the
/// migration lock so it can be taken after migrating.
const BOOTSTRAP_LOCK_KEY: i64 = 0x6f61_7574_6862_7374;

const DEFAULT_DISPLAY_NAME: &str = "Administrator";

#[derive(Default)]
pub struct Options {
    /// Ensure this email is a Global Admin of the tenant.
    pub admin_email: Option<String>,
    pub display_name: Option<String>,
    /// Issue a new one-time password for an existing admin.
    pub reset_password: bool,
    /// Bootstrap this regular tenant (created when missing) instead of the
    /// system tenant.
    pub tenant: Option<TenantOptions>,
    pub provisioning: Option<provisioning::Options>,
}

pub struct TenantOptions {
    pub slug: String,
    /// For a newly created tenant; default: the slug.
    pub display_name: Option<String>,
}

/// A freshly issued password or client secret. `Debug` is redacted so the
/// plaintext can't reach logs or panic messages by accident; read it
/// explicitly via [`Self::expose`].
#[derive(PartialEq, Eq)]
pub struct OneTimePassword(Zeroizing<String>);

impl OneTimePassword {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for OneTimePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OneTimePassword(<redacted>)")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AdminOutcome {
    Created { password: OneTimePassword },
    PasswordReset { password: OneTimePassword },
    Unchanged,
}

#[derive(Debug)]
pub struct Admin {
    pub email: String,
    pub outcome: AdminOutcome,
    pub disabled: bool,
}

#[derive(Debug)]
pub struct Report {
    pub tenant_slug: String,
    pub tenant_created: bool,
    pub admin: Option<Admin>,
    pub provisioning: Option<provisioning::Outcome>,
}

impl Report {
    /// Human-readable summary for stdout. Contains the one-time password /
    /// client secret when one was issued — never logged or stored in
    /// plaintext.
    pub fn render(&self) -> String {
        let slug = &self.tenant_slug;
        let mut out = vec![if self.tenant_created {
            format!("Created tenant `{slug}`.")
        } else {
            format!("Tenant `{slug}` already exists.")
        }];
        if let Some(admin) = &self.admin {
            render_admin(&mut out, admin);
        }
        if let Some(p) = &self.provisioning {
            render_provisioning(&mut out, p);
        }
        out.join("\n")
    }
}

fn render_admin(out: &mut Vec<String>, admin: &Admin) {
    let email = &admin.email;
    match &admin.outcome {
        AdminOutcome::Created { password } => {
            out.push(format!("Created Global Admin {email}."));
            out.push(one_time_password_notice(password.expose()));
        }
        AdminOutcome::PasswordReset { password } => {
            out.push(format!("Reset the password of {email}."));
            out.push(one_time_password_notice(password.expose()));
        }
        AdminOutcome::Unchanged => out.push(format!(
            "Global Admin {email} already exists; password unchanged \
             (pass --reset-password to issue a new one-time password)."
        )),
    }
    if admin.disabled {
        out.push(format!("WARNING: {email} is disabled and cannot sign in."));
    }
}

fn render_provisioning(out: &mut Vec<String>, p: &provisioning::Outcome) {
    let id = &p.client_id;
    out.push(if p.created {
        format!("Created provisioning app `{id}`.")
    } else {
        format!("Provisioning app `{id}` already exists.")
    });
    if p.role_assigned {
        out.push(format!(
            "Assigned management API role {} to `{id}`.",
            p.role
        ));
    }
    if let Some(removed) = p.role_removed {
        out.push(format!(
            "Removed management API role {removed} from `{id}`."
        ));
    }
    match &p.secret {
        Some(secret) => out.push(format!(
            "Client secret (shown only now):\n{}",
            secret.expose()
        )),
        None => out.push("Secret unchanged (pass --rotate-secret to issue a new one).".into()),
    }
}

fn one_time_password_notice(password: &str) -> String {
    format!("One-time password (shown only now; must be changed at first sign-in):\n{password}")
}

/// Migrates, then creates whatever is missing — all under one transaction
/// holding [`BOOTSTRAP_LOCK_KEY`].
pub async fn run(
    db: &DatabaseConnection,
    config: &Config,
    opts: &Options,
) -> anyhow::Result<Report> {
    if opts.admin_email.is_none() && opts.provisioning.is_none() {
        anyhow::bail!("nothing to bootstrap: give an admin email and/or a provisioning app");
    }
    db::migrate(db).await?;

    let txn = db.begin().await.context("starting bootstrap transaction")?;
    txn.execute_raw(Statement::from_sql_and_values(
        txn.get_database_backend(),
        "SELECT pg_advisory_xact_lock($1)",
        [BOOTSTRAP_LOCK_KEY.into()],
    ))
    .await
    .context("acquiring bootstrap lock")?;

    // Same rule as `serve`: a stored system tenant under another slug is
    // refused, or renamed with SYSTEM_TENANT_RENAME=1.
    let outcome = directory::reconcile_system_slug(&txn, config, SlugVia::Bootstrap).await?;
    if let SlugOutcome::Renamed { .. } = outcome {
        builtin_apps::reconcile_all(&txn, config).await?;
    }
    let (tenant, tenant_created) = ensure_tenant(&txn, config, opts.tenant.as_ref()).await?;
    let admin = match &opts.admin_email {
        Some(email) => Some(ensure_admin(&txn, config, &tenant, email, opts).await?),
        None => None,
    };
    let provisioning = match &opts.provisioning {
        Some(p) => Some(provisioning::ensure(&txn, &tenant, p).await?),
        None => None,
    };
    txn.commit().await.context("committing bootstrap")?;

    Ok(Report {
        tenant_slug: tenant.slug,
        tenant_created,
        admin,
        provisioning,
    })
}

async fn ensure_tenant(
    txn: &DatabaseTransaction,
    config: &Config,
    wanted: Option<&TenantOptions>,
) -> anyhow::Result<(tenants::Model, bool)> {
    let Some(wanted) = wanted else {
        return Ok(match directory::find_system_tenant(txn).await? {
            Some(tenant) => (tenant, false),
            None => (directory::create_system_tenant(txn, config).await?, true),
        });
    };
    if let Some(tenant) = directory::find_tenant_by_slug(txn, &wanted.slug).await? {
        return Ok((tenant, false));
    }
    let name = wanted.display_name.as_deref().unwrap_or(&wanted.slug);
    let new = NewTenant {
        slug: &wanted.slug,
        display_name: name,
    };
    // Key generation under the bootstrap lock: acceptable for a one-shot CLI.
    let keys = directory::generate_tenant_keys().await?;
    let tenant = directory::insert_tenant(txn, config, new, &keys).await?;
    // Like `POST /api/v1/tenants`, but in the new tenant's own log: there
    // may be no system tenant to record it in.
    audit::record(
        txn,
        audit::Event {
            tenant_id: tenant.id,
            actor: Actor::System,
            event_type: EventType::TenantCreate,
            target: Some(Target::Tenant(tenant.id)),
            outcome: entity::enums::Outcome::Success,
            ip: None,
            details: json!({ "slug": tenant.slug }),
        },
    )
    .await?;
    Ok((tenant, true))
}

async fn ensure_admin(
    txn: &DatabaseTransaction,
    config: &Config,
    tenant: &tenants::Model,
    email: &str,
    opts: &Options,
) -> anyhow::Result<Admin> {
    let (admin, outcome) = match directory::find_user_by_email(txn, tenant.id, email).await? {
        None => {
            let password = OneTimePassword(Zeroizing::new(password::generate_one_time()?));
            let user = directory::create_user(
                txn,
                tenant.id,
                NewUser {
                    email,
                    display_name: opts.display_name.as_deref().unwrap_or(DEFAULT_DISPLAY_NAME),
                    password: Some(password.expose()),
                    must_change_password: true,
                    email_verified: false,
                    disabled: false,
                },
            )
            .await?;
            (user, AdminOutcome::Created { password })
        }
        Some(user) if opts.reset_password => {
            let password = OneTimePassword(Zeroizing::new(password::generate_one_time()?));
            directory::set_password(
                txn,
                &config.master_key,
                tenant.id,
                user.id,
                password.expose(),
                true,
            )
            .await?;
            (user, AdminOutcome::PasswordReset { password })
        }
        Some(user) => (user, AdminOutcome::Unchanged),
    };
    // Also for a pre-existing user: the point of bootstrap is that this email
    // ends up a Global Admin.
    directory::assign_directory_role(txn, tenant.id, admin.id, DirectoryRole::GlobalAdmin).await?;
    let users::Model {
        email, disabled, ..
    } = admin;
    Ok(Admin {
        email,
        outcome,
        disabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn otp(value: &str) -> OneTimePassword {
        OneTimePassword(Zeroizing::new(value.to_owned()))
    }

    fn report(outcome: AdminOutcome) -> Report {
        Report {
            tenant_slug: "system".into(),
            tenant_created: false,
            admin: Some(Admin {
                email: "root@example.com".into(),
                outcome,
                disabled: false,
            }),
            provisioning: None,
        }
    }

    #[test]
    fn password_is_printed_only_when_issued() {
        let created = report(AdminOutcome::Created {
            password: otp("pw-123"),
        })
        .render();
        assert!(created.contains("Created Global Admin root@example.com"));
        assert!(created.contains("\npw-123"));

        let reset = report(AdminOutcome::PasswordReset {
            password: otp("pw-456"),
        })
        .render();
        assert!(reset.contains("pw-456"));

        let unchanged = report(AdminOutcome::Unchanged).render();
        assert!(!unchanged.contains("pw-"));
        assert!(unchanged.contains("password unchanged"));
        assert!(unchanged.contains("--reset-password"));
    }

    #[test]
    fn debug_never_shows_the_password() {
        let r = report(AdminOutcome::Created {
            password: otp("pw-secret"),
        });
        assert!(!format!("{r:?}").contains("pw-secret"));
    }

    #[test]
    fn disabled_admin_is_warned_about() {
        let mut r = report(AdminOutcome::Unchanged);
        if let Some(admin) = r.admin.as_mut() {
            admin.disabled = true;
        }
        r.tenant_created = true;
        let text = r.render();
        assert!(text.contains("Created tenant `system`"));
        assert!(text.contains("WARNING"));
    }

    #[test]
    fn provisioning_secret_is_printed_only_when_issued() {
        let outcome = |secret: Option<&str>| provisioning::Outcome {
            client_id: "ci".into(),
            created: secret.is_some(),
            role: "Directory.ReadWrite.All",
            role_assigned: secret.is_some(),
            role_removed: None,
            secret: secret.map(|s| OneTimePassword(Zeroizing::new(s.into()))),
        };
        let mut r = report(AdminOutcome::Unchanged);
        r.admin = None;
        r.provisioning = Some(outcome(Some("sec-1")));
        let text = r.render();
        assert!(text.contains("Created provisioning app `ci`"));
        assert!(text.contains("Assigned management API role Directory.ReadWrite.All"));
        assert!(text.contains("\nsec-1"));
        assert!(!format!("{r:?}").contains("sec-1"));
        r.provisioning = Some(outcome(None));
        let text = r.render();
        assert!(text.contains("already exists"));
        assert!(text.contains("--rotate-secret"));
        assert!(!text.contains("sec-"));
        assert!(!text.contains("Removed"));
        let mut downgraded = outcome(None);
        downgraded.role_removed = Some("Directory.ReadWrite.All");
        r.provisioning = Some(downgraded);
        assert!(
            r.render()
                .contains("Removed management API role Directory.ReadWrite.All from `ci`")
        );
    }
}
