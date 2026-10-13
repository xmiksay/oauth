//! `oauth bootstrap`: idempotently ensure the `system` tenant and a Global
//! Admin in it exist. Safe to re-run (e.g. from every deploy).

use anyhow::Context;
use entity::{enums::DirectoryRole, users};
use sea_orm::{ConnectionTrait, DatabaseConnection, Statement, TransactionTrait};
use zeroize::Zeroizing;

use crate::{
    config::Config,
    db,
    directory::{self, NewUser, password, slug::SYSTEM_TENANT_SLUG},
};

/// Serializes concurrent bootstraps ("oauthbst" in ASCII); distinct from the
/// migration lock so it can be taken after migrating.
const BOOTSTRAP_LOCK_KEY: i64 = 0x6f61_7574_6862_7374;

const DEFAULT_DISPLAY_NAME: &str = "Administrator";

pub struct Options {
    pub admin_email: String,
    pub display_name: Option<String>,
    /// Issue a new one-time password for an existing admin.
    pub reset_password: bool,
}

/// A freshly issued password. `Debug` is redacted so the plaintext can't reach
/// logs or panic messages by accident; read it explicitly via [`Self::expose`].
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
pub struct Report {
    pub tenant_created: bool,
    pub admin_email: String,
    pub admin: AdminOutcome,
    pub admin_disabled: bool,
}

impl Report {
    /// Human-readable summary for stdout. Contains the one-time password when
    /// one was issued — it is never logged or stored in plaintext.
    pub fn render(&self) -> String {
        let mut out = Vec::new();
        out.push(if self.tenant_created {
            format!("Created tenant `{SYSTEM_TENANT_SLUG}`.")
        } else {
            format!("Tenant `{SYSTEM_TENANT_SLUG}` already exists.")
        });
        let email = &self.admin_email;
        match &self.admin {
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
        if self.admin_disabled {
            out.push(format!("WARNING: {email} is disabled and cannot sign in."));
        }
        out.join("\n")
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
    db::migrate(db).await?;

    let txn = db.begin().await.context("starting bootstrap transaction")?;
    txn.execute_raw(Statement::from_sql_and_values(
        txn.get_database_backend(),
        "SELECT pg_advisory_xact_lock($1)",
        [BOOTSTRAP_LOCK_KEY.into()],
    ))
    .await
    .context("acquiring bootstrap lock")?;

    let (tenant, tenant_created) = match directory::find_system_tenant(&txn).await? {
        Some(tenant) => (tenant, false),
        None => (directory::create_system_tenant(&txn, config).await?, true),
    };

    let (admin, outcome) =
        match directory::find_user_by_email(&txn, tenant.id, &opts.admin_email).await? {
            None => {
                let password = OneTimePassword(Zeroizing::new(password::generate_one_time()?));
                let user = directory::create_user(
                    &txn,
                    tenant.id,
                    NewUser {
                        email: &opts.admin_email,
                        display_name: opts.display_name.as_deref().unwrap_or(DEFAULT_DISPLAY_NAME),
                        password: Some(password.expose()),
                        must_change_password: true,
                    },
                )
                .await?;
                (user, AdminOutcome::Created { password })
            }
            Some(user) if opts.reset_password => {
                let password = OneTimePassword(Zeroizing::new(password::generate_one_time()?));
                directory::set_password(&txn, tenant.id, user.id, password.expose(), true).await?;
                (user, AdminOutcome::PasswordReset { password })
            }
            Some(user) => (user, AdminOutcome::Unchanged),
        };
    // Also for a pre-existing user: the point of bootstrap is that this email
    // ends up a Global Admin.
    directory::assign_directory_role(&txn, tenant.id, admin.id, DirectoryRole::GlobalAdmin).await?;
    txn.commit().await.context("committing bootstrap")?;

    let users::Model {
        email, disabled, ..
    } = admin;
    Ok(Report {
        tenant_created,
        admin_email: email,
        admin: outcome,
        admin_disabled: disabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn otp(value: &str) -> OneTimePassword {
        OneTimePassword(Zeroizing::new(value.to_owned()))
    }

    fn report(admin: AdminOutcome) -> Report {
        Report {
            tenant_created: false,
            admin_email: "root@example.com".into(),
            admin,
            admin_disabled: false,
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
        r.admin_disabled = true;
        r.tenant_created = true;
        let text = r.render();
        assert!(text.contains("Created tenant `system`"));
        assert!(text.contains("WARNING"));
    }
}
