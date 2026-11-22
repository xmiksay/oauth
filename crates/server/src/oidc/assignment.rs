//! "Assignment required" (Entra model): an app with `assignment_required`
//! only lets principals holding one of its roles get tokens to or for it.
//! A user holds a role directly or through a group; an app through an
//! application permission. Only effective roles count (those whose
//! `allowed_member_types` admit the principal kind), the same set that
//! becomes the `roles` claim, so "assigned" never means an empty `roles`.
//!
//! Checked at authorize (before consent), on code redemption and on every
//! refresh, so removing an assignment stops new tokens; access tokens
//! already issued stay valid until they expire.

use entity::applications;
use sea_orm::ConnectionTrait;
use uuid::Uuid;

use crate::tokens::principal;

/// `error_description` of every refusal (which app isn't said: the client
/// learns nothing about the user's other assignments).
pub const NOT_ASSIGNED: &str = "the user or client is not assigned to the application";

/// The apps among `apps` that require assignment, each once (the client
/// can be its own resource).
fn requiring<'a>(apps: &[Option<&'a applications::Model>]) -> Vec<&'a applications::Model> {
    let mut out: Vec<&applications::Model> = Vec::new();
    for app in apps.iter().flatten() {
        if app.assignment_required && !out.iter().any(|a| a.id == app.id) {
            out.push(app);
        }
    }
    out
}

/// Whether the user may get a delegated token issued to `client` (for
/// `resource`, if any).
pub async fn user_may_use(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
    client: &applications::Model,
    resource: Option<&applications::Model>,
) -> anyhow::Result<bool> {
    let apps = requiring(&[Some(client), resource]);
    if apps.is_empty() {
        return Ok(true);
    }
    let groups = principal::user_groups(conn, tenant_id, user_id).await?;
    for app in apps {
        let roles = principal::user_roles(conn, tenant_id, app.id, user_id, &groups).await?;
        if roles.is_empty() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `client` may get an app-only token for `resource`.
pub async fn app_may_use(
    conn: &impl ConnectionTrait,
    client: &applications::Model,
    resource: &applications::Model,
) -> anyhow::Result<bool> {
    if !resource.assignment_required {
        return Ok(true);
    }
    let roles = principal::app_roles(conn, resource.tenant_id, resource.id, client.id).await?;
    Ok(!roles.is_empty())
}

#[cfg(test)]
mod tests {
    use entity::enums::{AccessTokenFormat, ClientType, GroupsClaimFormat, SigningAlg};

    use super::*;

    fn app(required: bool) -> applications::Model {
        let now = chrono::Utc::now().fixed_offset();
        applications::Model {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            client_id: "x".into(),
            display_name: "x".into(),
            client_type: ClientType::Confidential,
            builtin: false,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            web_origins: Vec::new(),
            identifier_uri: None,
            access_token_format: AccessTokenFormat::Jwt,
            signing_alg: SigningAlg::Rs256,
            groups_claim_format: GroupsClaimFormat::Id,
            device_code_enabled: false,
            mfa_policy: entity::enums::AppMfaPolicy::Inherit,
            assignment_required: required,
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 3600,
            created_at: now,
            updated_at: now,
        }
    }

    fn ids(apps: &[&applications::Model]) -> Vec<Uuid> {
        apps.iter().map(|a| a.id).collect()
    }

    #[test]
    fn only_apps_requiring_assignment_are_checked() {
        let (open, closed) = (app(false), app(true));
        assert!(requiring(&[Some(&open), None]).is_empty());
        assert!(requiring(&[Some(&open), Some(&open)]).is_empty());
        assert_eq!(ids(&requiring(&[Some(&open), Some(&closed)])), [closed.id]);
        assert_eq!(ids(&requiring(&[Some(&closed), None])), [closed.id]);
    }

    #[test]
    fn a_client_that_is_its_own_resource_is_checked_once() {
        let closed = app(true);
        assert_eq!(
            ids(&requiring(&[Some(&closed), Some(&closed)])),
            [closed.id]
        );
        let other = app(true);
        assert_eq!(
            ids(&requiring(&[Some(&closed), Some(&other)])),
            [closed.id, other.id]
        );
    }
}
