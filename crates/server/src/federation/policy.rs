//! What a verified upstream identity leads to (pure).

use entity::enums::IdpPolicy;

use super::id_token::Claims;

/// Next step for an upstream identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Linked to an enabled user: sign them in.
    SignIn,
    /// Policy `jit`: create a user with the verified email and link it.
    CreateUser,
    /// Policy `link_only`: the user signs in locally, which links it.
    PendingLink,
    Refuse(Refusal),
}

/// Why sign-in was refused; the code is what the login page shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Disabled,
    NoVerifiedEmail,
    /// The email belongs to an existing user: never linked automatically.
    EmailTaken,
    /// Policy `deny` and the identity isn't linked.
    NotLinked,
    /// Policy `jit` on an IdP with `email_domains`, and the verified email
    /// is of another domain.
    EmailDomainNotAllowed,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::Disabled => "account_disabled",
            Self::NoVerifiedEmail => "upstream_no_email",
            Self::EmailTaken => "account_exists",
            Self::NotLinked => "not_linked",
            Self::EmailDomainNotAllowed => "email_domain_not_allowed",
        }
    }
}

/// `linked` = the linked user's `disabled` flag, if the identity is linked;
/// `domain_allowed` = the verified email's domain may be provisioned;
/// `email_taken` = a local user has the upstream email (only asked for JIT).
pub fn decide(
    linked: Option<bool>,
    policy: IdpPolicy,
    verified_email: bool,
    domain_allowed: bool,
    email_taken: bool,
) -> Decision {
    match (linked, policy) {
        (Some(true), _) => Decision::Refuse(Refusal::Disabled),
        (Some(false), _) => Decision::SignIn,
        (None, IdpPolicy::Deny) => Decision::Refuse(Refusal::NotLinked),
        (None, IdpPolicy::LinkOnly) => Decision::PendingLink,
        (None, IdpPolicy::Jit) if !verified_email => Decision::Refuse(Refusal::NoVerifiedEmail),
        (None, IdpPolicy::Jit) if !domain_allowed => {
            Decision::Refuse(Refusal::EmailDomainNotAllowed)
        }
        (None, IdpPolicy::Jit) if email_taken => Decision::Refuse(Refusal::EmailTaken),
        (None, IdpPolicy::Jit) => Decision::CreateUser,
    }
}

/// Whether JIT may provision `email`: an IdP with `email_domains` only
/// for addresses of those domains.
pub fn domain_allowed(email_domains: &[String], email: &str) -> bool {
    email_domains.is_empty()
        || super::idps::email_domain(email).is_some_and(|d| email_domains.contains(&d))
}

/// The verified email JIT may use: present and `email_verified`.
pub fn verified_email(claims: &Claims) -> Option<&str> {
    claims
        .email
        .as_deref()
        .filter(|e| claims.email_verified && !e.trim().is_empty())
}

/// Whether the upstream's own MFA replaces ours: only if the IdP is
/// trusted for it, and the token says so (`amr` ∋ `mfa`, or `acr` equals
/// the configured value).
pub fn upstream_mfa(trust: bool, mfa_acr: Option<&str>, claims: &Claims) -> bool {
    trust
        && (claims.amr.iter().any(|a| a == "mfa")
            || mfa_acr.is_some_and(|want| claims.acr.as_deref() == Some(want)))
}

/// `amr` of a federated sign-in (before any local second factor).
pub fn amr(upstream_mfa: bool) -> Vec<String> {
    let mut amr = vec!["fed".to_owned()];
    if upstream_mfa {
        amr.push("mfa".to_owned());
    }
    amr
}

#[cfg(test)]
mod tests {
    use super::*;
    use IdpPolicy::{Deny, Jit, LinkOnly};

    #[test]
    fn linked_identities_sign_in_unless_disabled() {
        for policy in [Jit, LinkOnly, Deny] {
            assert_eq!(
                decide(Some(false), policy, false, false, true),
                Decision::SignIn
            );
            assert_eq!(
                decide(Some(true), policy, true, true, false),
                Decision::Refuse(Refusal::Disabled)
            );
        }
    }

    #[test]
    fn unknown_identities_follow_the_policy() {
        assert_eq!(
            decide(None, Deny, true, true, false),
            Decision::Refuse(Refusal::NotLinked)
        );
        assert_eq!(
            decide(None, LinkOnly, false, false, true),
            Decision::PendingLink
        );
        assert_eq!(decide(None, Jit, true, true, false), Decision::CreateUser);
        assert_eq!(
            decide(None, Jit, false, true, false),
            Decision::Refuse(Refusal::NoVerifiedEmail)
        );
        assert_eq!(
            decide(None, Jit, true, false, false),
            Decision::Refuse(Refusal::EmailDomainNotAllowed)
        );
        // Never linked by email, even when it is verified.
        assert_eq!(
            decide(None, Jit, true, true, true),
            Decision::Refuse(Refusal::EmailTaken)
        );
        let domains = ["contoso.com".to_owned()];
        assert!(domain_allowed(&[], "a@any.example"));
        assert!(domain_allowed(&domains, "a@Contoso.com"));
        assert!(!domain_allowed(&domains, "a@contoso.com.evil"));
        assert!(!domain_allowed(&domains, "a@sub.contoso.com"));
    }

    fn claims(email: Option<&str>, verified: bool, amr: &[&str], acr: Option<&str>) -> Claims {
        Claims {
            subject: "s".into(),
            email: email.map(str::to_owned),
            email_verified: verified,
            name: None,
            amr: amr.iter().map(|a| (*a).to_owned()).collect(),
            acr: acr.map(str::to_owned),
            auth_time: None,
        }
    }

    #[test]
    fn verified_email_needs_the_flag() {
        assert_eq!(
            verified_email(&claims(Some("a@b"), true, &[], None)),
            Some("a@b")
        );
        assert_eq!(verified_email(&claims(Some("a@b"), false, &[], None)), None);
        assert_eq!(verified_email(&claims(None, true, &[], None)), None);
        assert_eq!(verified_email(&claims(Some(" "), true, &[], None)), None);
    }

    #[test]
    fn upstream_mfa_needs_trust_and_evidence() {
        let mfa = claims(None, false, &["pwd", "mfa"], None);
        assert!(upstream_mfa(true, None, &mfa));
        assert!(!upstream_mfa(false, None, &mfa));
        let acr = claims(None, false, &["pwd"], Some("urn:mfa"));
        assert!(upstream_mfa(true, Some("urn:mfa"), &acr));
        assert!(!upstream_mfa(true, Some("urn:other"), &acr));
        assert!(!upstream_mfa(true, None, &acr));
        assert_eq!(amr(false), ["fed"]);
        assert_eq!(amr(true), ["fed", "mfa"]);
    }
}
