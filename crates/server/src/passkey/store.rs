//! `webauthn_credentials` and `users.webauthn_handle` persistence.

use anyhow::{Context, anyhow};
use aws_lc_rs::rand;
use entity::{users, webauthn_credentials};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, sea_query::Expr,
};
use uuid::Uuid;

use super::PasskeyError;
use crate::webauthn::{assert::Asserted, register::Registered};

/// Passkeys one user may hold.
pub const MAX_PER_USER: u64 = 20;
const NAME_MAX_CHARS: usize = 64;

/// The user's WebAuthn user handle, created on first use. The conditional
/// UPDATE makes concurrent first registrations agree on one handle.
pub async fn ensure_handle(
    conn: &impl ConnectionTrait,
    user: &users::Model,
) -> anyhow::Result<Vec<u8>> {
    if let Some(handle) = &user.webauthn_handle {
        return Ok(handle.clone());
    }
    let mut fresh = [0u8; 32];
    rand::fill(&mut fresh).map_err(|_| anyhow!("generating webauthn user handle"))?;
    users::Entity::update_many()
        .col_expr(users::Column::WebauthnHandle, Expr::value(fresh.to_vec()))
        .filter(users::Column::TenantId.eq(user.tenant_id))
        .filter(users::Column::Id.eq(user.id))
        .filter(users::Column::WebauthnHandle.is_null())
        .exec(conn)
        .await
        .context("storing webauthn user handle")?;
    let handle: Option<Option<Vec<u8>>> = users::Entity::find_by_id(user.id)
        .select_only()
        .column(users::Column::WebauthnHandle)
        .into_tuple()
        .one(conn)
        .await
        .context("reading webauthn user handle")?;
    handle
        .flatten()
        .context("user vanished while storing its handle")
}

pub async fn list(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<Vec<webauthn_credentials::Model>> {
    webauthn_credentials::Entity::find()
        .filter(webauthn_credentials::Column::TenantId.eq(tenant_id))
        .filter(webauthn_credentials::Column::UserId.eq(user_id))
        .order_by_asc(webauthn_credentials::Column::Id)
        .all(conn)
        .await
        .context("listing passkeys")
}

pub async fn count(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<u64> {
    webauthn_credentials::Entity::find()
        .filter(webauthn_credentials::Column::TenantId.eq(tenant_id))
        .filter(webauthn_credentials::Column::UserId.eq(user_id))
        .count(conn)
        .await
        .context("counting passkeys")
}

/// The passkey with WebAuthn credential id `credential_id` in this tenant.
pub async fn find_by_credential_id(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    credential_id: &[u8],
) -> anyhow::Result<Option<webauthn_credentials::Model>> {
    webauthn_credentials::Entity::find()
        .filter(webauthn_credentials::Column::TenantId.eq(tenant_id))
        .filter(webauthn_credentials::Column::CredentialId.eq(credential_id.to_vec()))
        .one(conn)
        .await
        .context("looking up passkey")
}

/// The user's passkey `id` (row id), if theirs.
pub async fn find_for_user(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
    id: Uuid,
) -> anyhow::Result<Option<webauthn_credentials::Model>> {
    webauthn_credentials::Entity::find_by_id(id)
        .filter(webauthn_credentials::Column::TenantId.eq(tenant_id))
        .filter(webauthn_credentials::Column::UserId.eq(user_id))
        .one(conn)
        .await
        .context("loading passkey")
}

/// A display name: trimmed, 1–64 characters, no control characters;
/// `None` / blank = "Passkey".
pub fn name(given: Option<&str>) -> Result<String, PasskeyError> {
    let name = given
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or("Passkey");
    if name.chars().count() > NAME_MAX_CHARS || name.chars().any(char::is_control) {
        return Err(PasskeyError::Invalid(
            "name must be 1-64 characters without control characters",
        ));
    }
    Ok(name.to_owned())
}

pub struct NewCredential<'a> {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub rp_id: &'a str,
    pub registered: &'a Registered,
    pub transports: Vec<String>,
    pub name: String,
}

/// Stores a verified credential. The caller holds the user's row lock, so
/// the per-user cap can't be raced past.
pub async fn insert(
    conn: &impl ConnectionTrait,
    new: NewCredential<'_>,
) -> Result<webauthn_credentials::Model, PasskeyError> {
    if count(conn, new.tenant_id, new.user_id).await? >= MAX_PER_USER {
        return Err(PasskeyError::Conflict(
            "the maximum number of passkeys is reached",
        ));
    }
    let reg = new.registered;
    let row = webauthn_credentials::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(new.tenant_id),
        user_id: Set(new.user_id),
        credential_id: Set(reg.credential_id.clone()),
        public_key: Set(reg.public_key.clone()),
        alg: Set(i32::try_from(reg.alg).context("COSE algorithm out of range")?),
        sign_count: Set(i64::from(reg.sign_count)),
        rp_id: Set(new.rp_id.to_owned()),
        transports: Set(new.transports),
        aaguid: Set(Uuid::from_bytes(reg.aaguid)),
        name: Set(new.name),
        backup_eligible: Set(reg.backup_eligible),
        backup_state: Set(reg.backup_state),
        created_at: Set(chrono::Utc::now().fixed_offset()),
        last_used_at: Set(None),
    };
    webauthn_credentials::Entity::insert(row)
        .exec_with_returning(conn)
        .await
        .map_err(|err| {
            if crate::directory::violates_any_unique(&err) {
                PasskeyError::Conflict("this passkey is already registered")
            } else {
                PasskeyError::Internal(anyhow::Error::new(err).context("storing passkey"))
            }
        })
}

/// Records a successful assertion. The counter condition is re-checked in
/// the statement, so of two racing assertions with the same counter only
/// one is accepted; `false` = the counter went backwards meanwhile.
pub async fn record_use(
    conn: &impl ConnectionTrait,
    credential: &webauthn_credentials::Model,
    asserted: Asserted,
) -> anyhow::Result<bool> {
    use webauthn_credentials::Column;
    let new = i64::from(asserted.sign_count);
    // Same rule as `assert::counter_ok`, evaluated against the row as it is now.
    let counter_ok = if new == 0 {
        Column::SignCount.eq(0)
    } else {
        Column::SignCount.lt(new)
    };
    let result = webauthn_credentials::Entity::update_many()
        .col_expr(Column::SignCount, Expr::value(new))
        .col_expr(Column::BackupState, Expr::value(asserted.backup_state))
        .col_expr(Column::LastUsedAt, Expr::current_timestamp())
        .filter(Column::Id.eq(credential.id))
        .filter(counter_ok)
        .exec(conn)
        .await
        .context("recording passkey use")?;
    Ok(result.rows_affected == 1)
}

pub async fn rename(
    conn: &impl ConnectionTrait,
    credential: &webauthn_credentials::Model,
    name: &str,
) -> anyhow::Result<webauthn_credentials::Model> {
    let mut row: webauthn_credentials::ActiveModel = credential.clone().into();
    row.name = Set(name.to_owned());
    sea_orm::ActiveModelTrait::update(row, conn)
        .await
        .context("renaming passkey")
}

/// Deletes one passkey, refusing to remove the user's last sign-in method
/// (password, passkeys, linked identities). `user` must be row-locked by the
/// caller, so two concurrent removals can't both pass the check.
pub async fn remove(
    conn: &impl ConnectionTrait,
    user: &users::Model,
    credential: &webauthn_credentials::Model,
) -> Result<(), PasskeyError> {
    if !crate::federation::identities::methods(conn, user)
        .await?
        .can_drop_passkey()
    {
        return Err(PasskeyError::Conflict(
            "the last sign-in method can't be removed: set a password first",
        ));
    }
    webauthn_credentials::Entity::delete_by_id(credential.id)
        .exec(conn)
        .await
        .context("removing passkey")?;
    Ok(())
}

/// Removes all of the user's passkeys (admin MFA reset); returns how many.
pub async fn remove_all(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<u64> {
    let result = webauthn_credentials::Entity::delete_many()
        .filter(webauthn_credentials::Column::TenantId.eq(tenant_id))
        .filter(webauthn_credentials::Column::UserId.eq(user_id))
        .exec(conn)
        .await
        .context("removing passkeys")?;
    Ok(result.rows_affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(name(None).unwrap(), "Passkey");
        assert_eq!(name(Some("  ")).unwrap(), "Passkey");
        assert_eq!(name(Some(" Phone ")).unwrap(), "Phone");
        assert_eq!(name(Some(&"é".repeat(64))).unwrap().chars().count(), 64);
        assert!(name(Some(&"x".repeat(65))).is_err());
        assert!(name(Some("a\nb")).is_err());
    }
}
