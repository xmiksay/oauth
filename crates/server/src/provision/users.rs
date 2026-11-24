//! Users: created with an optional password from the environment, updated
//! in place (display name, disabled), and deleted only when managed.

use anyhow::Context;
use entity::users;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder,
};
use serde_json::json;
use zeroize::Zeroizing;

use super::{
    Env,
    ctx::{Ctx, diff, update_line},
    spec::UserSpec,
};
use crate::{
    api::guard::{ensure_not_last_global_admin, lock_user},
    audit::{EventType, Target},
    directory::{self, NewUser, display_name},
};

fn password(spec: &UserSpec, env: Env<'_>) -> anyhow::Result<Option<Zeroizing<String>>> {
    let Some(var) = &spec.password_env else {
        return Ok(None);
    };
    let value = env(var).filter(|v| !v.is_empty()).with_context(|| {
        format!(
            "environment variable `{var}` (password of `{}`) is not set",
            spec.email
        )
    })?;
    Ok(Some(Zeroizing::new(value)))
}

/// Users `apply` disabled whose last-Global-Admin check and credential
/// revocation wait for [`finish_disabling`].
#[must_use]
pub struct Disabled(Vec<users::Model>);

pub async fn apply(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    specs: &[UserSpec],
    env: Env<'_>,
) -> anyhow::Result<Disabled> {
    let mut disabled = Vec::new();
    for spec in specs {
        let user = upsert(conn, cx, spec, env)
            .await
            .with_context(|| format!("user `{}`", spec.email))?;
        disabled.extend(user);
    }
    Ok(Disabled(disabled))
}

/// Runs after the directory roles are reconciled, so a file that makes
/// another user Global Admin may disable the current one: the rule checks
/// the end state, not the order of the steps.
/// Locks each user `FOR UPDATE` first, like the API: a sign-in that read
/// the user as enabled finishes before the revocation, which then ends its
/// session too (and queues its Back-Channel Logouts).
pub async fn finish_disabling(
    conn: &impl ConnectionTrait,
    cx: &Ctx,
    master_key: &[u8; 32],
    disabled: Disabled,
) -> anyhow::Result<()> {
    for user in disabled.0 {
        lock_user(conn, cx.tenant_id, user.id).await?;
        ensure_not_last_global_admin(conn, cx.tenant_id, user.id)
            .await
            .with_context(|| format!("disabling user `{}`", user.email))?;
        directory::revoke_credentials(conn, master_key, cx.tenant_id, user.id, None).await?;
    }
    Ok(())
}

async fn upsert(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    spec: &UserSpec,
    env: Env<'_>,
) -> anyhow::Result<Option<users::Model>> {
    let tenant_id = cx.tenant_id;
    let email = spec.email.trim();
    let Some(user) = directory::find_user_by_email(conn, tenant_id, email).await? else {
        let password = password(spec, env)?;
        let disabled = spec.disabled.unwrap_or(false);
        let user = directory::create_user(
            conn,
            tenant_id,
            NewUser {
                email,
                display_name: &spec.display_name,
                password: password.as_ref().map(|p| p.as_str()),
                // Like the API: an initial password is a temporary one unless the
                // file says otherwise.
                must_change_password: password.is_some()
                    && spec.must_change_password.unwrap_or(true),
                email_verified: false,
                disabled,
            },
        )
        .await?;
        let mut row: users::ActiveModel = user.clone().into();
        row.managed = Set(true);
        row.update(conn).await?;
        cx.kept.insert(user.id);
        let how = if password.is_some() {
            "set_by_apply"
        } else {
            "none"
        };
        let details = json!({ "email": user.email, "password": how, "disabled": disabled });
        cx.record(
            conn,
            format!("+ user {}", user.email),
            EventType::UserCreate,
            Some(Target::User(user.id)),
            details,
        )
        .await?;
        return Ok(None);
    };
    cx.kept.insert(user.id);
    let mut row: users::ActiveModel = user.clone().into();
    let mut fields = Vec::new();
    let name = display_name(&spec.display_name, "user")?;
    if name != user.display_name {
        row.display_name = Set(name);
        fields.push("display_name");
    }
    let disabling = spec.disabled == Some(true) && !user.disabled;
    if let Some(disabled) = spec.disabled.filter(|d| *d != user.disabled) {
        row.disabled = Set(disabled);
        fields.push("disabled");
    }
    if fields.is_empty() && user.managed {
        return Ok(None);
    }
    row.managed = Set(true);
    if !fields.is_empty() {
        row.updated_at = Set(chrono::Utc::now().fixed_offset());
    }
    let updated = row.update(conn).await?;
    let line = update_line(
        &format!("user {}", user.email),
        &diff(&user, &updated, &fields),
        !user.managed,
    );
    if fields.is_empty() {
        cx.note(line);
        return Ok(None);
    }
    let details = json!({ "fields": fields, "disabled": updated.disabled });
    cx.record(
        conn,
        line,
        EventType::UserUpdate,
        Some(Target::User(user.id)),
        details,
    )
    .await?;
    Ok(disabling.then_some(updated))
}

/// Locks the managed users the file no longer declares (`FOR UPDATE`, in id
/// order) and returns them for [`prune`]. Apply runs it before its first app
/// or consent write: the deletes come last, but their user locks must not
/// follow locks a token request takes after its user (`provision::run`).
pub async fn lock_stale(
    conn: &impl ConnectionTrait,
    cx: &Ctx,
) -> anyhow::Result<Vec<users::Model>> {
    let managed = users::Entity::find()
        .filter(users::Column::TenantId.eq(cx.tenant_id))
        .filter(users::Column::Managed.eq(true))
        .order_by_asc(users::Column::Id)
        .all(conn)
        .await?;
    let mut stale = Vec::new();
    for user in managed.into_iter().filter(|u| !cx.kept.contains(&u.id)) {
        stale.push(lock_user(conn, cx.tenant_id, user.id).await?);
    }
    Ok(stale)
}

/// Deletes the users [`lock_stale`] locked.
pub async fn prune(
    conn: &impl ConnectionTrait,
    cx: &mut Ctx,
    master_key: &[u8; 32],
    stale: Vec<users::Model>,
) -> anyhow::Result<()> {
    for user in stale {
        ensure_not_last_global_admin(conn, cx.tenant_id, user.id)
            .await
            .with_context(|| format!("deleting user `{}`", user.email))?;
        directory::delete_user(conn, master_key, cx.tenant_id, user.id).await?;
        let line = format!("- user {}", user.email);
        let details = json!({ "email": user.email });
        cx.record(
            conn,
            line,
            EventType::UserDelete,
            Some(Target::User(user.id)),
            details,
        )
        .await?;
    }
    Ok(())
}
