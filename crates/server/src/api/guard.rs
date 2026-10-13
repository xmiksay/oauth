//! Guards that need the database: administrator protection and the
//! last-Global-Admin rule.

use anyhow::Context;
use entity::{enums::DirectoryRole, users};
use sea_orm::{
    ActiveEnum, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, Statement,
};
use uuid::Uuid;

use super::auth::{Caller, directory_roles};
use crate::{
    authz,
    error::{AppError, AppResult},
};

/// The user `id` of the caller's tenant, else 404.
pub async fn find_user(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    id: Uuid,
) -> AppResult<users::Model> {
    users::Entity::find_by_id(id)
        .filter(users::Column::TenantId.eq(tenant_id))
        .one(conn)
        .await?
        .ok_or(AppError::NotFound)
}

/// [`find_user`] holding the row lock until the transaction ends: role
/// checks on the user (administrator protection) and role assignments to
/// them serialize, so a check can't pass on roles that change meanwhile.
pub async fn lock_user(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    id: Uuid,
) -> AppResult<users::Model> {
    users::Entity::find_by_id(id)
        .filter(users::Column::TenantId.eq(tenant_id))
        .lock_exclusive()
        .one(conn)
        .await?
        .ok_or(AppError::NotFound)
}

/// An object named in a request BODY that doesn't exist is a 400 (the URL
/// itself was fine); objects in the path are 404s.
pub fn referenced<T>(result: AppResult<T>, what: &str) -> AppResult<T> {
    result.map_err(|err| match err {
        AppError::NotFound => AppError::BadRequest(format!("{what} not found")),
        other => other,
    })
}

/// A unique violation becomes 409 with `msg`; anything else stays a 500.
pub fn conflict_on_unique(err: sea_orm::DbErr, msg: &str) -> AppError {
    if crate::directory::violates_any_unique(&err) {
        AppError::Conflict(msg.to_owned())
    } else {
        err.into()
    }
}

/// 403 unless the caller may modify `user_id` (`authz::can_modify_user`).
pub async fn ensure_can_modify_user(
    conn: &impl ConnectionTrait,
    caller: &Caller,
    user_id: Uuid,
) -> AppResult<()> {
    lock_user(conn, caller.tenant_id(), user_id).await?;
    let roles = directory_roles(conn, caller.tenant_id(), user_id).await?;
    if authz::can_modify_user(&caller.principal, &roles) {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "only a Global Admin can modify an administrator".into(),
        ))
    }
}

/// Call inside the transaction that is about to remove `user_id`'s
/// effective GlobalAdmin role (unassign, disable, delete): 409 if no other
/// enabled Global Admin would remain. A per-tenant advisory lock makes
/// concurrent removals serialize, so two admins can't demote each other at
/// once and leave the tenant without one.
pub async fn ensure_not_last_global_admin(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    let backend = conn.get_database_backend();
    conn.execute_raw(Statement::from_sql_and_values(
        backend,
        "SELECT pg_advisory_xact_lock(hashtextextended('global-admins:' || $1::text, 0))",
        [tenant_id.into()],
    ))
    .await
    .context("taking the global admin lock")?;
    let row = conn
        .query_one_raw(Statement::from_sql_and_values(
            backend,
            r"SELECT
                  bool_or(d.user_id = $2) AS target_is_admin,
                  count(*) FILTER (WHERE d.user_id <> $2 AND NOT u.disabled) AS others
              FROM directory_role_assignments d
              JOIN users u ON u.tenant_id = d.tenant_id AND u.id = d.user_id
              WHERE d.tenant_id = $1 AND d.role = $3",
            [
                tenant_id.into(),
                user_id.into(),
                DirectoryRole::GlobalAdmin.to_value().into(),
            ],
        ))
        .await
        .context("counting global admins")?
        .context("count query returned no row")?;
    let target_is_admin: Option<bool> = row.try_get("", "target_is_admin").context("reading")?;
    let others: i64 = row.try_get("", "others").context("reading")?;
    if target_is_admin == Some(true) && others == 0 {
        return Err(AppError::Conflict(
            "the tenant's last enabled Global Admin cannot be removed, disabled or deleted".into(),
        ));
    }
    Ok(())
}
