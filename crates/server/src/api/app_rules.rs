//! Rules shared by the app-registration endpoints: lookup, built-in
//! protection, credential protection of privileged apps, token lifetime
//! bounds and per-app object caps.

use anyhow::Context;
use entity::{applications, enums::ClientType};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, Statement};
use uuid::Uuid;

use super::Caller;
use crate::{
    authz::{Access, Area},
    error::{AppError, AppResult},
};

/// `applications.access_token_ttl_secs` CHECK bounds.
pub const ACCESS_TTL: std::ops::RangeInclusive<i32> = 300..=86_400;
/// Refresh-token family lifetime caps (also a DB CHECK for the larger one).
/// Public clients keep refresh tokens in browsers / devices: one week.
pub const MAX_REFRESH_TTL_CONFIDENTIAL: i32 = 90 * 86_400;
pub const MAX_REFRESH_TTL_PUBLIC: i32 = 7 * 86_400;
/// Default for new public clients (the built-in SPAs' lifetime).
pub const DEFAULT_REFRESH_TTL_PUBLIC: i32 = 86_400;

pub const MAX_SECRETS: u64 = 50;
pub const MAX_SCOPES: u64 = 200;
pub const MAX_ROLES: u64 = 200;
pub const MAX_REQUIRED_PERMISSIONS: u64 = 200;

pub fn refresh_ttl(client_type: ClientType, ttl: i32) -> AppResult<()> {
    let max = match client_type {
        ClientType::Confidential => MAX_REFRESH_TTL_CONFIDENTIAL,
        ClientType::Public => MAX_REFRESH_TTL_PUBLIC,
    };
    if (1..=max).contains(&ttl) {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "refresh_token_ttl_secs must be 1-{max} for this client type"
        )))
    }
}

/// 409 once an app already has `cap` objects of a kind.
pub fn ensure_below(count: u64, cap: u64, what: &str) -> AppResult<()> {
    if count < cap {
        Ok(())
    } else {
        Err(AppError::Conflict(format!(
            "an application can have at most {cap} {what}"
        )))
    }
}

/// The app `id` of the tenant, else 404.
pub async fn find_app(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    id: Uuid,
) -> AppResult<applications::Model> {
    applications::Entity::find_by_id(id)
        .filter(applications::Column::TenantId.eq(tenant_id))
        .one(conn)
        .await?
        .ok_or(AppError::NotFound)
}

/// [`find_app`] holding the row lock until the transaction ends: creates of
/// child objects serialize per app, so the per-app caps can't be overshot
/// by concurrent requests.
pub async fn lock_app(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    id: Uuid,
) -> AppResult<applications::Model> {
    applications::Entity::find_by_id(id)
        .filter(applications::Column::TenantId.eq(tenant_id))
        .lock_exclusive()
        .one(conn)
        .await?
        .ok_or(AppError::NotFound)
}

/// Built-in registrations are provisioned by the server; their secrets,
/// scopes, roles and required permissions are fixed.
pub fn ensure_not_builtin(app: &applications::Model) -> AppResult<()> {
    if app.builtin {
        Err(AppError::Forbidden(
            "built-in applications can't be changed this way".into(),
        ))
    } else {
        Ok(())
    }
}

/// Authorizes an app write, then loads (and locks) the app and refuses
/// built-ins.
pub async fn writable_app(
    conn: &impl ConnectionTrait,
    caller: &Caller,
    app_id: Uuid,
) -> AppResult<applications::Model> {
    caller.require(Area::Applications, Access::Write)?;
    let app = lock_app(conn, caller.tenant_id(), app_id).await?;
    ensure_not_builtin(&app)?;
    Ok(app)
}

/// Whoever controls a client's credentials (secrets) or where its codes go
/// (redirect URIs) can act as it. An app holding management-API access — an
/// app role assignment or a consent grant on the built-in API — is
/// therefore only reconfigurable by a GlobalAdmin; otherwise an
/// ApplicationAdmin could borrow its `Directory.ReadWrite.All`.
pub async fn ensure_may_manage_credentials(
    conn: &impl ConnectionTrait,
    caller: &Caller,
    app: &applications::Model,
) -> AppResult<()> {
    if caller.principal.is_global_admin() {
        return Ok(());
    }
    let row = conn
        .query_one_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            r"SELECT EXISTS (
                  SELECT 1 FROM app_role_assignments a
                  JOIN applications r ON r.id = a.resource_application_id
                  WHERE a.tenant_id = $1 AND a.client_application_id = $2 AND r.builtin
              ) OR EXISTS (
                  SELECT 1 FROM consent_grants g
                  JOIN applications r ON r.id = g.resource_application_id
                  WHERE g.tenant_id = $1 AND g.client_application_id = $2 AND r.builtin
              ) AS privileged",
            [app.tenant_id.into(), app.id.into()],
        ))
        .await
        .context("checking management API access of the app")?
        .context("privilege query returned no row")?;
    let privileged: bool = row.try_get("", "privileged").context("reading privilege")?;
    if privileged {
        Err(AppError::Forbidden(
            "the app holds management API access; only a Global Admin can change its \
             credentials or redirect URIs"
                .into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_lifetimes_are_capped_per_client_type() {
        assert!(refresh_ttl(ClientType::Confidential, MAX_REFRESH_TTL_CONFIDENTIAL).is_ok());
        assert!(refresh_ttl(ClientType::Confidential, MAX_REFRESH_TTL_CONFIDENTIAL + 1).is_err());
        assert!(refresh_ttl(ClientType::Public, MAX_REFRESH_TTL_PUBLIC).is_ok());
        assert!(refresh_ttl(ClientType::Public, MAX_REFRESH_TTL_PUBLIC + 1).is_err());
        assert!(refresh_ttl(ClientType::Public, i32::MAX).is_err());
        assert!(refresh_ttl(ClientType::Confidential, 0).is_err());
    }

    #[test]
    fn caps() {
        assert!(ensure_below(49, MAX_SECRETS, "secrets").is_ok());
        assert!(matches!(
            ensure_below(50, MAX_SECRETS, "secrets"),
            Err(AppError::Conflict(_))
        ));
    }
}
