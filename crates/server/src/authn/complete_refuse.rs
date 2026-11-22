//! The ways sign-in completion (`complete`) ends a transaction without
//! issuing anything: each claims the login transaction and, for a device
//! request, denies the device code (see [`close`]).

use entity::{
    applications,
    enums::{LoginStage, Outcome as AuditOutcome},
    users,
};
use sea_orm::TransactionTrait;
use serde_json::json;
use uuid::Uuid;

use super::{AuthnError, AuthnResult, Outcome, ctx::Ctx, device_code, mfa_policy, tx::LoadedTx};
use crate::{
    metrics,
    oidc::{assignment, error::ErrorCode},
};

/// The login_required redirect (transaction burnt) when the MFA policy was
/// tightened while the consent screen was up. A consent-only transaction
/// can't step up from here (`finish` would reuse its single-factor
/// session): a new request does.
pub(super) async fn refuse_single_factor(
    ctx: &Ctx<'_>,
    tx: &LoadedTx,
    user: &users::Model,
) -> AuthnResult<Option<Outcome>> {
    let (app, amr) = (tx.row.application_id, &tx.row.amr);
    let missing = mfa_policy::missing(ctx.state, ctx.tenant, app, &tx.req, user.id, amr).await?;
    if missing.is_none() {
        return Ok(None);
    }
    close(ctx, tx, LoginStage::Consent, user.id, "mfa_required").await?;
    let msg = "multi-factor authentication is now required; sign in again";
    Ok(Some(ctx.error_redirect(
        &tx.req,
        ErrorCode::LoginRequired,
        msg,
    )?))
}

/// The access_denied redirect (transaction burnt) when `user` holds no
/// assignment the client or resource requires; `None` when they may go on.
/// Runs before anything consent-related: an unassigned user is never asked
/// to consent, nor is a grant stored for them.
pub(super) async fn refuse_unassigned(
    ctx: &Ctx<'_>,
    tx: &LoadedTx,
    from: LoginStage,
    user: &users::Model,
    client: &applications::Model,
    resource: Option<&applications::Model>,
) -> AuthnResult<Option<Outcome>> {
    let conn = &ctx.state.db;
    if assignment::user_may_use(conn, client.tenant_id, user.id, client, resource).await? {
        return Ok(None);
    }
    close(ctx, tx, from, user.id, "not_assigned").await?;
    let refused = match tx.req.device {
        // The device still gets `access_denied`; the page says why.
        Some(_) => Outcome::Redirect {
            url: device_code::result_url(ctx, device_code::NOT_ASSIGNED),
            cookies: Vec::new(),
        },
        None => ctx.error_redirect(&tx.req, ErrorCode::AccessDenied, assignment::NOT_ASSIGNED)?,
    };
    Ok(Some(refused))
}

/// `finish` found the user disabled (or deleted) once it held their lock:
/// the disable committed while it waited. Closes the transaction (so a
/// device request gets `access_denied` instead of polling until it
/// expires) and records the refusal as the password step does. Call it
/// after dropping `finish`'s DB transaction.
pub(super) async fn refuse_disabled(
    ctx: &Ctx<'_>,
    tx: &LoadedTx,
    from: LoginStage,
    user_id: Uuid,
) -> AuthnResult<Outcome> {
    close(ctx, tx, from, user_id, "account_disabled").await?;
    metrics::login("disabled");
    let details = json!({ "reason": "disabled" });
    ctx.audit_sign_in(&ctx.state.db, Some(user_id), AuditOutcome::Failure, details)
        .await?;
    Err(AuthnError::AccountDisabled)
}

/// Claims the transaction without issuing anything and, for a device
/// request, denies the device code with its audit event — in one DB
/// transaction, so a refused device never keeps polling
/// `authorization_pending` after its login transaction is gone.
pub(super) async fn close(
    ctx: &Ctx<'_>,
    tx: &LoadedTx,
    from: LoginStage,
    user_id: Uuid,
    reason: &'static str,
) -> AuthnResult<()> {
    let txn = ctx.state.db.begin().await?;
    // The user before the transaction row (deleting the user locks it, then
    // cascades to the row); `deny_for` writes the user into the device row.
    crate::backchannel::lock_user(&txn, ctx.tenant.id, user_id).await?;
    if super::tx::take(&txn, tx.row.id, from).await? {
        device_code::deny_for(&txn, ctx, tx, user_id, reason).await?;
    }
    txn.commit().await?;
    Ok(())
}
