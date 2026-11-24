//! Human-readable lines of a bootstrap [`super::Report`].

use super::{Admin, AdminOutcome, provisioning};

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
    out.push(if p.created {
        format!("Created provisioning app `{id}`.")
    } else if p.adopted {
        format!("WARNING: adopted existing app `{id}` as the provisioning app.")
    } else {
        format!("Provisioning app `{id}` already exists.")
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
