//! Users and directory role assignments.

use anyhow::Context;
use entity::{
    directory_role_assignments,
    enums::{DirectoryRole, UserType},
    users,
};
use sea_orm::{
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    sea_query::{Expr, ExprTrait, Func, OnConflict},
};
use uuid::Uuid;

use super::{
    DirectoryError, display_name, password, reject_control_chars, violates_foreign_key,
    violates_unique,
};

pub struct NewUser<'a> {
    pub email: &'a str,
    pub display_name: &'a str,
    /// `None` creates a user without a local password.
    pub password: Option<&'a str>,
    pub must_change_password: bool,
}

/// Minimal shape check; deliverability is proven by verification (M1b), not
/// by a regex.
fn normalize_email(raw: &str) -> Result<String, DirectoryError> {
    let email = raw.trim();
    // First, so the error below never echoes control characters back.
    reject_control_chars(email, "email address")?;
    let valid = email.len() <= 254
        && !email.chars().any(char::is_whitespace)
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.is_empty() && !domain.contains('@')
        });
    if !valid {
        return Err(DirectoryError::Invalid(format!(
            "`{email}` is not a valid email address"
        )));
    }
    Ok(email.to_owned())
}

pub async fn create_user(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    new: NewUser<'_>,
) -> Result<users::Model, DirectoryError> {
    let email = normalize_email(new.email)?;
    let display_name = display_name(new.display_name, "user")?;
    let password_hash = match new.password {
        Some(pw) => {
            password::validate(pw)?;
            Some(password::hash(pw).await?)
        }
        None => None,
    };
    let row = users::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tenant_id),
        user_type: Set(UserType::Member),
        email: Set(email.clone()),
        email_verified: Set(false),
        display_name: Set(display_name),
        password_hash: Set(password_hash),
        must_change_password: Set(new.must_change_password),
        disabled: Set(false),
        ..Default::default()
    };
    users::Entity::insert(row)
        .exec_with_returning(conn)
        .await
        .map_err(|err| {
            if violates_unique(&err, "users_tenant_email") {
                DirectoryError::EmailTaken(email)
            } else if violates_foreign_key(&err) {
                DirectoryError::NotFound
            } else {
                anyhow::Error::new(err).context("inserting user").into()
            }
        })
}

/// Case-insensitive lookup. Both sides go through Postgres `lower()` — the
/// same function as the `lower(email)` unique index — so lookup and
/// uniqueness agree even where Rust's and the DB locale's case folding
/// differ (non-ASCII).
pub async fn find_user_by_email(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    email: &str,
) -> anyhow::Result<Option<users::Model>> {
    // Stored emails never contain control chars, and Postgres rejects NUL in
    // a parameter — answer "not found" instead of a 500.
    if email.chars().any(char::is_control) {
        return Ok(None);
    }
    users::Entity::find()
        .filter(users::Column::TenantId.eq(tenant_id))
        .filter(
            Expr::expr(Func::lower(Expr::col(users::Column::Email)))
                .eq(Func::lower(Expr::val(email.trim()))),
        )
        .one(conn)
        .await
        .context("looking up user by email")
}

pub async fn set_password(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
    new_password: &str,
    must_change_password: bool,
) -> Result<(), DirectoryError> {
    password::validate(new_password)?;
    let hash = password::hash(new_password).await?;
    let result = users::Entity::update_many()
        .col_expr(users::Column::PasswordHash, Expr::value(hash))
        .col_expr(
            users::Column::MustChangePassword,
            Expr::value(must_change_password),
        )
        .col_expr(users::Column::UpdatedAt, Expr::current_timestamp())
        .filter(users::Column::TenantId.eq(tenant_id))
        .filter(users::Column::Id.eq(user_id))
        .exec(conn)
        .await
        .context("updating password")?;
    if result.rows_affected == 0 {
        return Err(DirectoryError::NotFound);
    }
    Ok(())
}

/// Idempotent: assigning a role the user already holds is a no-op.
pub async fn assign_directory_role(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
    role: DirectoryRole,
) -> Result<(), DirectoryError> {
    use directory_role_assignments::Column;
    let row = directory_role_assignments::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tenant_id),
        user_id: Set(user_id),
        role: Set(role),
        ..Default::default()
    };
    directory_role_assignments::Entity::insert(row)
        .on_conflict(
            OnConflict::columns([Column::TenantId, Column::UserId, Column::Role])
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(conn)
        .await
        .map_err(|err| {
            if violates_foreign_key(&err) {
                DirectoryError::NotFound
            } else {
                anyhow::Error::new(err)
                    .context("assigning directory role")
                    .into()
            }
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_trimmed_and_shape_checked() {
        assert_eq!(
            normalize_email("  Ann@Example.com ").unwrap(),
            "Ann@Example.com"
        );
        for bad in [
            "",
            "ann",
            "@example.com",
            "ann@",
            "a b@example.com",
            "a@b@c",
        ] {
            assert!(normalize_email(bad).is_err(), "{bad} accepted");
        }
        assert!(normalize_email(&format!("{}@x.io", "a".repeat(250))).is_err());
    }

    #[test]
    fn emails_with_control_characters_are_invalid() {
        for bad in ["ann\0@example.com", "ann@exa\u{7f}mple.com"] {
            let err = normalize_email(bad).unwrap_err();
            assert!(
                matches!(&err, DirectoryError::Invalid(m) if m.contains("control characters")),
                "{bad:?}: {err}"
            );
        }
    }
}
