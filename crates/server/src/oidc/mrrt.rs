//! Multi-resource refresh tokens (Entra-style): a refresh token redeemed with
//! scopes of a resource other than its grant's mints an access token for
//! that resource — when the user (or an admin, tenant-wide) has consented
//! to every requested scope for this client now, and the sign-in behind the
//! token satisfies the MFA policy of the tenant, client and that resource.
//! Nothing is stored: the rotated refresh token keeps the family's original
//! grant, so every such redemption is re-checked against live consent.

use entity::{app_scopes, applications, refresh_tokens};
use sea_orm::DatabaseTransaction;

use super::{
    error::{OAuthError, OAuthResult},
    refresh_grant::invalid_scope,
    scope,
};
use crate::{
    authn::mfa_policy,
    consent::{self, Decision},
    tenancy::Tenant,
};

/// Why a redemption for another resource is refused, if it is.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    NoScopes,
    Consent,
    Mfa,
}

fn refusal(scopes: &[app_scopes::Model], consent: &Decision, mfa_missing: bool) -> Option<Refusal> {
    if scopes.is_empty() {
        Some(Refusal::NoScopes)
    } else if *consent != Decision::Granted {
        Some(Refusal::Consent)
    } else if mfa_missing {
        Some(Refusal::Mfa)
    } else {
        None
    }
}

impl From<Refusal> for OAuthError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::NoScopes => invalid_scope("the client has no permissions on the resource"),
            Refusal::Consent => OAuthError::invalid_grant(
                "the resource has not been consented to for this client; sign in interactively",
            ),
            Refusal::Mfa => OAuthError::invalid_grant(
                "the resource requires multi-factor authentication; sign in interactively",
            ),
        }
    }
}

/// The resource and expanded scope values `row` may be redeemed for.
/// `found` = the resource the scope prefix names in this tenant (apps of
/// other tenants are never found: `scope::find_resource` filters by tenant).
/// `txn` must be the transaction that issues the token: the consent rows
/// are read `FOR SHARE`, so a withdrawal racing this redemption waits for
/// its commit and then revokes the opaque token it issued.
pub(super) async fn resolve(
    txn: &DatabaseTransaction,
    tenant: &Tenant,
    client: &applications::Model,
    row: &refresh_tokens::Model,
    found: Option<applications::Model>,
    values: &[String],
) -> OAuthResult<(applications::Model, Vec<String>)> {
    let resource = found.ok_or_else(|| invalid_scope("unknown resource"))?;
    let scopes = scope::resolve_delegated(txn, client.id, &resource, values)
        .await?
        .ok_or_else(|| invalid_scope("the resource does not expose a requested scope"))?;
    // Built-in clients are pre-consented, as at authorize.
    let decision = if client.builtin {
        Decision::Granted
    } else {
        // Locked: see `refresh_grant::grant` (the caller's transaction).
        let granted =
            consent::granted_scopes(txn, tenant.id, client.id, resource.id, row.user_id, true)
                .await?;
        consent::evaluate(&scopes, &granted, false)
    };
    let mfa_missing = !mfa_policy::is_mfa(&row.amr)
        && mfa_policy::required(txn, tenant, client.id, Some(resource.id)).await?;
    if let Some(r) = refusal(&scopes, &decision, mfa_missing) {
        return Err(r.into());
    }
    Ok((resource, scopes.into_iter().map(|s| s.value).collect()))
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn scope(value: &str) -> app_scopes::Model {
        app_scopes::Model {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            application_id: Uuid::nil(),
            value: value.into(),
            description: String::new(),
            admin_consent_required: false,
            created_at: chrono::Utc::now().fixed_offset(),
        }
    }

    #[test]
    fn refusals_in_order() {
        let read = [scope("read")];
        let ok = Decision::Granted;
        let ask = Decision::NeedsUser(vec!["read".into()]);
        let admin = Decision::NeedsAdmin(vec!["read".into()]);
        assert_eq!(refusal(&read, &ok, false), None);
        assert_eq!(refusal(&[], &ok, false), Some(Refusal::NoScopes));
        assert_eq!(refusal(&read, &ask, false), Some(Refusal::Consent));
        assert_eq!(refusal(&read, &admin, true), Some(Refusal::Consent));
        assert_eq!(refusal(&read, &ok, true), Some(Refusal::Mfa));
    }
}
