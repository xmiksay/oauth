//! Tenant slug validation. The slug is the first DNS label of every tenant
//! host (`{slug}.{PUBLIC_URL host}`), so it must be a valid label and must not
//! take a name operators conventionally give to other services on the same
//! domain.

use super::DirectoryError;

/// Default slug of the built-in tenant created by `oauth bootstrap`
/// (`SYSTEM_TENANT_SLUG` overrides it). Stays reserved whatever the
/// configured slug is, so a renamed system tenant's old host can't be taken.
pub const DEFAULT_SYSTEM_TENANT_SLUG: &str = "system";

/// Labels that are not tenant names. WHY: under a wildcard DNS record and
/// certificate every label resolves to us, so a tenant called `www`, `mail`
/// or `status` would capture the hostname an operator (or a user typing it)
/// expects to be the website, mail server or status page — and could serve a
/// convincing sign-in page there. `system` is the default bootstrap tenant;
/// [`validate`] also reserves the configured system slug.
pub const RESERVED_SLUGS: &[&str] = &[
    "www",
    "api",
    "app",
    "admin",
    "auth",
    "login",
    "sso",
    "id",
    "oauth",
    "account",
    "accounts",
    "mail",
    "email",
    "smtp",
    "imap",
    "pop",
    "pop3",
    "mx",
    "webmail",
    "autoconfig",
    "autodiscover",
    "ns",
    "ns1",
    "ns2",
    "dns",
    "ftp",
    "vpn",
    "cdn",
    "static",
    "assets",
    "status",
    "metrics",
    "localhost",
    DEFAULT_SYSTEM_TENANT_SLUG,
];

/// Checks the shape `^[a-z0-9][a-z0-9-]{1,62}$` (mirrored by a DB CHECK).
/// Used as the cheap pre-check before any slug lookup.
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

/// Full validation for user-chosen (regular tenant) slugs: format, DNS label
/// rules the DB CHECK predates, and reserved names — including
/// `system_slug`, the configured slug of the system tenant.
pub fn validate(slug: &str, system_slug: &str) -> Result<(), DirectoryError> {
    if slug == system_slug || RESERVED_SLUGS.contains(&slug) {
        return Err(reserved(slug));
    }
    label_rules(slug)
}

/// Validation of the configured system tenant slug (`SYSTEM_TENANT_SLUG`):
/// the rules of [`validate`], except that the default `system` is allowed.
pub fn validate_system(slug: &str) -> Result<(), DirectoryError> {
    if slug != DEFAULT_SYSTEM_TENANT_SLUG && RESERVED_SLUGS.contains(&slug) {
        return Err(reserved(slug));
    }
    label_rules(slug)
}

fn reserved(slug: &str) -> DirectoryError {
    DirectoryError::Invalid(format!("tenant slug `{slug}` is reserved"))
}

fn label_rules(slug: &str) -> Result<(), DirectoryError> {
    validate_format(slug)?;
    if slug.ends_with('-') {
        return Err(DirectoryError::Invalid(format!(
            "tenant slug `{slug}` must not end with '-' (it is a DNS label)"
        )));
    }
    // `xn--…` is punycode (a homograph of some Unicode name) and RFC 5891
    // reserves every `??--` label for such encodings.
    if slug.get(2..4) == Some("--") {
        return Err(DirectoryError::Invalid(format!(
            "tenant slug `{slug}` must not have '--' as its 3rd and 4th characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYS: &str = DEFAULT_SYSTEM_TENANT_SLUG;

    #[test]
    fn accepts_valid_slugs() {
        for slug in [
            "ab",
            "contoso",
            "a-b-c",
            "a--b",
            "0day",
            "x9",
            "src",
            "healthz",
            &"a".repeat(63),
        ] {
            assert!(validate(slug, SYS).is_ok(), "{slug} rejected");
        }
    }

    #[test]
    fn rejects_bad_format() {
        for slug in [
            "",
            "a",
            "-ab",
            "ab-",
            "xn--80ak6aa92e",
            "ab--c",
            "Contoso",
            "con toso",
            "con_toso",
            "conto.so",
            "čau",
            "@vite",
            ".git",
            &"a".repeat(64),
        ] {
            let err = validate(slug, SYS).unwrap_err();
            assert!(matches!(err, DirectoryError::Invalid(_)), "{slug}: {err}");
            assert!(validate_system(slug).is_err(), "{slug}");
        }
    }

    #[test]
    fn rejects_reserved() {
        for slug in RESERVED_SLUGS {
            let err = validate(slug, SYS).unwrap_err().to_string();
            assert!(err.contains("reserved"), "{slug}: {err}");
        }
    }

    #[test]
    fn configured_system_slug_is_reserved_too() {
        assert!(validate("config", SYS).is_ok());
        let err = validate("config", "config").unwrap_err().to_string();
        assert!(err.contains("reserved"), "{err}");
        // `system` stays reserved after the system tenant moved away from it.
        assert!(validate(DEFAULT_SYSTEM_TENANT_SLUG, "config").is_err());
    }

    #[test]
    fn system_slug_validation() {
        for slug in [DEFAULT_SYSTEM_TENANT_SLUG, "config", "ab"] {
            assert!(validate_system(slug).is_ok(), "{slug} rejected");
        }
        for slug in [
            "www",
            "api",
            "admin",
            "ab-",
            "xn--80ak6aa92e",
            "Config",
            "a",
        ] {
            assert!(validate_system(slug).is_err(), "{slug} accepted");
        }
    }
}
