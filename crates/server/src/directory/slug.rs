//! Tenant slug validation. The slug is the first path segment of every tenant
//! URL (`/{slug}/oauth2/…`, `/{slug}/admin`), so it must not collide with
//! top-level routes.

use super::DirectoryError;

/// The built-in tenant created by `oauth bootstrap`.
pub const SYSTEM_TENANT_SLUG: &str = "system";

/// Slugs that would shadow a top-level path. WHY each exists: the backend
/// router (`app.rs`) serves `/healthz`, `/readyz` (`health.rs`), static SPA
/// files at the root such as `/assets/…` (`spa.rs`) and the management API
/// under `/api/…` (`api`);
/// the Vite dev server owns `/src`, `/node_modules` and `/@…` (see
/// `web/dev-proxy.ts`, which must not proxy them as tenants); `/metrics` and
/// `/.well-known` are conventional root paths; `system` is the bootstrap
/// tenant. Keep in sync when adding a root route.
pub const RESERVED_SLUGS: &[&str] = &[
    "api",
    "assets",
    "static",
    "src",
    "node_modules",
    "healthz",
    "readyz",
    "metrics",
    "well-known",
    SYSTEM_TENANT_SLUG,
];

/// Checks the shape `^[a-z0-9][a-z0-9-]{1,62}$` (mirrored by a DB CHECK).
pub fn validate_format(slug: &str) -> Result<(), DirectoryError> {
    let mut chars = slug.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if first_ok && rest_ok && (2..=63).contains(&slug.len()) {
        Ok(())
    } else {
        Err(DirectoryError::Invalid(format!(
            "tenant slug `{slug}` must be 2-63 characters of a-z, 0-9 and '-', \
             starting with a letter or digit"
        )))
    }
}

/// Full validation for user-chosen slugs: format + reserved names.
pub fn validate(slug: &str) -> Result<(), DirectoryError> {
    // `@…` / `.…` (Vite internals, dotfiles) need no entry: the format
    // already requires a leading letter or digit.
    if RESERVED_SLUGS.contains(&slug) {
        return Err(DirectoryError::Invalid(format!(
            "tenant slug `{slug}` is reserved"
        )));
    }
    validate_format(slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_slugs() {
        for slug in ["ab", "contoso", "a-b-c", "0day", "x9", &"a".repeat(63)] {
            assert!(validate(slug).is_ok(), "{slug} rejected");
        }
    }

    #[test]
    fn rejects_bad_format() {
        for slug in [
            "",
            "a",
            "-ab",
            "Contoso",
            "con toso",
            "con_toso",
            "conto.so",
            "čau",
            &"a".repeat(64),
        ] {
            let err = validate(slug).unwrap_err();
            assert!(matches!(err, DirectoryError::Invalid(_)), "{slug}: {err}");
        }
    }

    #[test]
    fn rejects_reserved() {
        for slug in RESERVED_SLUGS {
            let err = validate(slug).unwrap_err().to_string();
            assert!(err.contains("reserved"), "{slug}: {err}");
        }
    }

    #[test]
    fn rejects_vite_and_dot_prefixes_by_format() {
        for slug in ["@vite", "@fs", ".well-known", ".git"] {
            let err = validate(slug).unwrap_err().to_string();
            assert!(
                err.contains("starting with a letter or digit"),
                "{slug}: {err}"
            );
        }
    }

    #[test]
    fn system_slug_has_valid_format() {
        assert!(validate_format(SYSTEM_TENANT_SLUG).is_ok());
        assert!(validate(SYSTEM_TENANT_SLUG).is_err());
    }
}
