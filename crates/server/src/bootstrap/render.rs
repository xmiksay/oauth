//! Human-readable lines of a bootstrap [`super::Report`].

use super::{Admin, AdminOutcome, provisioning, takeover::Takeover};
use crate::directory::builtin_apps::{ROLE_READ_ALL, ROLE_READ_WRITE_ALL};

pub(super) fn admin(out: &mut Vec<String>, admin: &Admin) {
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

pub(super) fn provisioning(out: &mut Vec<String>, p: &provisioning::Outcome) {
    let id = &p.client_id;
    out.push(match (p.created, p.adopted) {
        (true, _) => format!("Created provisioning app `{id}`."),
        (false, None) => format!("Provisioning app `{id}` already exists."),
        (false, Some(Takeover::NoRole)) => {
            format!("WARNING: adopted existing app `{id}` as the provisioning app.")
        }
        (false, Some(Takeover::Upgrade)) => format!(
            "WARNING: upgraded existing app `{id}` from {ROLE_READ_ALL} \
             to {ROLE_READ_WRITE_ALL} (--adopt-app)."
        ),
        (false, Some(Takeover::Downgrade)) => format!(
            "WARNING: downgraded existing app `{id}`, which bootstrap did not make, \
             from {ROLE_READ_WRITE_ALL} to {ROLE_READ_ALL} (--adopt-app)."
        ),
        (false, Some(Takeover::RotateSecret)) => format!(
            "WARNING: issuing a secret for existing app `{id}`, which bootstrap \
             did not make (--adopt-app)."
        ),
    });
    // An existing app changing its management API role is never routine:
    // an admin may have given the role to a third-party app.
    let warn = if p.created { "" } else { "WARNING: " };
    if p.role_assigned {
        out.push(format!(
            "{warn}Assigned management API role {} to `{id}`.",
            p.role
        ));
    }
    if let Some(removed) = p.role_removed {
        out.push(format!(
            "{warn}Removed management API role {removed} from `{id}`."
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
