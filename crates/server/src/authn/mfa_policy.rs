//! MFA enforcement (`tenants.mfa_policy`, `applications.mfa_policy`): a
//! sign-in to an app needs a second factor when the tenant or the client
//! app or the requested resource app requires one. Applied when a sign-in
//! completes (`complete::proceed`) and when an existing session is reused
//! (`oidc::authorize`, the device flow): a single-factor session is then
//! stepped up instead of reused.

use anyhow::Context;
use entity::{
    applications,
    enums::{AppMfaPolicy, LoginStage, MfaPolicy},
    sessions, tenants,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::{app::AppState, oidc::params::AuthRequest};

/// Whether `amr` already records a multi-factor sign-in (a local second
/// factor, a passwordless passkey or an upstream IdP trusted for MFA).
pub fn is_mfa(amr: &[String]) -> bool {
    amr.iter().any(|a| a == "mfa")
}

/// The effective policy: required when anyone requires it.
pub fn effective(tenant: MfaPolicy, apps: impl IntoIterator<Item = AppMfaPolicy>) -> bool {
    tenant == MfaPolicy::Required || apps.into_iter().any(|p| p == AppMfaPolicy::Required)
}

/// Whether a sign-in of `tenant` to `client_app_id` for `req` needs MFA.
pub async fn required(
    conn: &impl ConnectionTrait,
    tenant: &tenants::Model,
    client_app_id: Uuid,
    req: &AuthRequest,
) -> anyhow::Result<bool> {
    if tenant.mfa_policy == MfaPolicy::Required {
        return Ok(true);
    }
    let ids: Vec<Uuid> = std::iter::once(client_app_id)
        .chain(req.resource_id)
        .collect();
    let apps = applications::Entity::find()
        .filter(applications::Column::TenantId.eq(tenant.id))
        .filter(applications::Column::Id.is_in(ids))
        .all(conn)
        .await
        .context("loading app MFA policies")?;
    Ok(effective(
        tenant.mfa_policy,
        apps.iter().map(|a| a.mfa_policy),
    ))
}

/// The step that makes a sign-in multi-factor: the user's own factor, or
/// enrolment of one when they have none.
pub async fn stage(state: &AppState, tenant_id: Uuid, user_id: Uuid) -> anyhow::Result<LoginStage> {
    Ok(
        match super::password::has_second_factor(state, tenant_id, user_id).await? {
            true => LoginStage::Mfa,
            false => LoginStage::MfaEnroll,
        },
    )
}

/// For a sign-in about to complete with `amr`: the MFA step it still needs.
pub async fn missing(
    state: &AppState,
    tenant: &tenants::Model,
    client_app_id: Uuid,
    req: &AuthRequest,
    user_id: Uuid,
    amr: &[String],
) -> anyhow::Result<Option<LoginStage>> {
    if is_mfa(amr) || !required(&state.db, tenant, client_app_id, req).await? {
        return Ok(None);
    }
    Ok(Some(stage(state, tenant.id, user_id).await?))
}

/// For an existing session about to be reused: the step-up stage it needs
/// first, if any.
pub async fn step_up(
    state: &AppState,
    tenant: &tenants::Model,
    client_app_id: Uuid,
    req: &AuthRequest,
    session: &sessions::Model,
) -> anyhow::Result<Option<LoginStage>> {
    missing(
        state,
        tenant,
        client_app_id,
        req,
        session.user_id,
        &session.amr,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apps_can_only_tighten() {
        use AppMfaPolicy::{Inherit, Required};
        assert!(!effective(MfaPolicy::Optional, []));
        assert!(!effective(MfaPolicy::Optional, [Inherit, Inherit]));
        assert!(effective(MfaPolicy::Optional, [Inherit, Required]));
        assert!(effective(MfaPolicy::Required, []));
        assert!(effective(MfaPolicy::Required, [Inherit]));
    }

    #[test]
    fn mfa_is_read_from_amr() {
        let amr = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(!is_mfa(&amr(&["pwd"])));
        assert!(!is_mfa(&amr(&["fed"])));
        assert!(is_mfa(&amr(&["pwd", "otp", "mfa"])));
        assert!(is_mfa(&amr(&["fed", "mfa"])));
        assert!(is_mfa(&amr(&["hwk", "user", "mfa"])));
    }
}
