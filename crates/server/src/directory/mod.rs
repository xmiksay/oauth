//! Directory service: tenants, users and directory roles as plain functions
//! over a connection or transaction. HTTP handlers (`api`) map
//! [`DirectoryError`] into [`AppError`].

pub mod builtin_apps;
pub mod password;
pub mod slug;
mod tenants;
mod users;

use sea_orm::{DbErr, RuntimeErr, sqlx};

use crate::error::AppError;

pub(crate) use tenants::create_system_tenant;
pub use tenants::{
    NewTenant, TenantKeys, create_tenant, find_system_tenant, find_tenant_by_slug,
    generate_tenant_keys, insert_tenant, invalid_enabled_slugs,
};
pub use users::{
    NewUser, assign_directory_role, create_user, find_user_by_email, normalize_email,
    revoke_credentials, set_password, set_password_keeping,
};

#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    /// Input failed validation; the message is safe to show to the caller.
    #[error("{0}")]
    Invalid(String),
    #[error("tenant slug `{0}` is already taken")]
    SlugTaken(String),
    #[error("a user with email `{0}` already exists in this tenant")]
    EmailTaken(String),
    #[error("not found")]
    NotFound,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<DirectoryError> for AppError {
    fn from(err: DirectoryError) -> Self {
        match err {
            DirectoryError::Invalid(msg) => Self::BadRequest(msg),
            DirectoryError::SlugTaken(_) | DirectoryError::EmailTaken(_) => {
                Self::Conflict(err.to_string())
            }
            DirectoryError::NotFound => Self::NotFound,
            DirectoryError::Internal(err) => Self::Internal(err),
        }
    }
}

const PG_UNIQUE_VIOLATION: &str = "23505";
const PG_FOREIGN_KEY_VIOLATION: &str = "23503";

/// The Postgres error behind `err`, if the statement reached the database.
fn pg_error(err: &DbErr) -> Option<&dyn sqlx::error::DatabaseError> {
    match err {
        DbErr::Exec(RuntimeErr::SqlxError(e)) | DbErr::Query(RuntimeErr::SqlxError(e)) => {
            match e.as_ref() {
                sqlx::Error::Database(db) => Some(db.as_ref()),
                _ => None,
            }
        }
        _ => None,
    }
}

/// True if `err` violated the unique index / constraint named `name`
/// (structured SQLSTATE + constraint name, not message matching).
pub(crate) fn violates_unique(err: &DbErr, name: &str) -> bool {
    pg_error(err).is_some_and(|e| {
        e.code().as_deref() == Some(PG_UNIQUE_VIOLATION) && e.constraint() == Some(name)
    })
}

pub(crate) fn violates_foreign_key(err: &DbErr) -> bool {
    pg_error(err).is_some_and(|e| e.code().as_deref() == Some(PG_FOREIGN_KEY_VIOLATION))
}

/// True if `err` violated any unique index / constraint.
pub(crate) fn violates_any_unique(err: &DbErr) -> bool {
    pg_error(err).is_some_and(|e| e.code().as_deref() == Some(PG_UNIQUE_VIOLATION))
}

/// Invisible formatting characters (Unicode `Cf`) usable for spoofing:
/// bidi overrides/isolates (e.g. U+202E flips displayed text) and zero-width
/// characters. Not the whole `Cf` category — std has no such check and a
/// table crate isn't worth it — but the ones that matter for display.
const INVISIBLE_FORMAT_CHARS: &[(char, char)] = &[
    ('\u{00AD}', '\u{00AD}'), // soft hyphen
    ('\u{061C}', '\u{061C}'), // Arabic letter mark
    ('\u{180E}', '\u{180E}'), // Mongolian vowel separator
    ('\u{200B}', '\u{200F}'), // zero-width space/(non-)joiner, LRM, RLM
    ('\u{202A}', '\u{202E}'), // bidi embeddings and overrides
    ('\u{2060}', '\u{2064}'), // word joiner, invisible operators
    ('\u{2066}', '\u{206F}'), // bidi isolates, deprecated format chars
    ('\u{FEFF}', '\u{FEFF}'), // zero-width no-break space / BOM
    ('\u{FFF9}', '\u{FFFB}'), // interlinear annotation
];

fn is_invisible_format(c: char) -> bool {
    INVISIBLE_FORMAT_CHARS
        .iter()
        .any(|&(lo, hi)| (lo..=hi).contains(&c))
}

/// Rejects control characters (NUL can't be stored in Postgres `text` and
/// would surface as a 500) and invisible formatting characters (spoofing).
pub fn reject_control_chars(value: &str, what: &str) -> Result<(), DirectoryError> {
    if value
        .chars()
        .any(|c| c.is_control() || is_invisible_format(c))
    {
        return Err(DirectoryError::Invalid(format!(
            "{what} must not contain control characters or invisible formatting characters"
        )));
    }
    Ok(())
}

/// Trims and bounds a human-readable name.
pub fn display_name(raw: &str, what: &str) -> Result<String, DirectoryError> {
    let name = raw.trim();
    reject_control_chars(name, &format!("{what} display name"))?;
    if name.is_empty() || name.chars().count() > 256 {
        return Err(DirectoryError::Invalid(format!(
            "{what} display name must be 1-256 characters"
        )));
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_map_to_client_safe_app_errors() {
        assert!(matches!(
            AppError::from(DirectoryError::Invalid("x".into())),
            AppError::BadRequest(_)
        ));
        assert!(matches!(
            AppError::from(DirectoryError::SlugTaken("x".into())),
            AppError::Conflict(_)
        ));
        assert!(matches!(
            AppError::from(DirectoryError::EmailTaken("x".into())),
            AppError::Conflict(_)
        ));
        assert!(matches!(
            AppError::from(DirectoryError::NotFound),
            AppError::NotFound
        ));
        assert!(matches!(
            AppError::from(DirectoryError::Internal(anyhow::anyhow!("db down"))),
            AppError::Internal(_)
        ));
    }

    #[test]
    fn display_names_are_trimmed_and_bounded() {
        assert_eq!(display_name("  Contoso ", "tenant").unwrap(), "Contoso");
        // Ordinary non-ASCII text stays allowed.
        assert!(display_name("Žofie Nováková 東京", "user").is_ok());
        assert!(display_name("   ", "tenant").is_err());
        assert!(display_name(&"x".repeat(257), "tenant").is_err());
        for bad in [
            "a\0b",
            "line\nbreak",
            "tab\there",
            "esc\u{1b}",
            "admin\u{202E}nimda",
            "zero\u{200B}width",
            "bom\u{FEFF}",
            "isolate\u{2066}x",
        ] {
            let err = display_name(bad, "tenant").unwrap_err();
            assert!(
                err.to_string().contains("control characters"),
                "{bad:?}: {err}"
            );
        }
    }
}
