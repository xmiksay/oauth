//! Stage `link`: a parked upstream identity waits for the local sign-in that
//! links it. The IdP must still be enabled with policy `link_only`, and the
//! signing-in user must not already have an identity there.

use anyhow::Context;
use entity::{
    enums::{IdpPolicy, LoginStage, NotifyEvent},
    identity_providers, login_transactions, user_identities, users,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryFilter, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::{AuthnError, AuthnResult, ctx::Ctx, federation_login::audit_user, tx};
use crate::{
    audit,
    federation::{
        identities::{self, LinkError, NewIdentity, Pending},
        idps,
    },
    notify,
};

/// The IdP configuration an upstream sign-in was verified against
/// (`login_transactions.federated`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdpRef {
    pub idp_id: Uuid,
    pub generation: i64,
}

/// Locks, FIRST in the transaction completing a sign-in, the IdP row it
/// depends on: an upstream sign-in's (`federated`) or a parked identity's.
/// Every writer takes the IdP row before login transactions — a repoint
/// does too (`FOR UPDATE`, then releasing parked logins) — so the two can't
/// deadlock. `Some(idp_id)` = the upstream sign-in's IdP was disabled or
/// repointed since: the sign-in must not complete. (A parked identity's IdP
/// changing only skips the link, `link_or_skip`.)
pub async fn lock_first(
    txn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    row: &login_transactions::Model,
) -> AuthnResult<Option<Uuid>> {
    if let Some(raw) = &row.federated {
        let via: IdpRef =
            serde_json::from_value(raw.clone()).context("decoding federated sign-in")?;
        let current = idps::lock_current(txn, ctx.tenant.id, via.idp_id, via.generation).await?;
        if current.is_none() {
            return Ok(Some(via.idp_id));
        }
    }
    if let Some(raw) = &row.pending_identity {
        let pending = decode(raw)?;
        idps::lock_current(txn, ctx.tenant.id, pending.idp_id, pending.generation).await?;
    }
    Ok(None)
}

/// Ends a transaction whose upstream sign-in no longer holds (`lock_first`):
/// it is deleted, the failure audited.
pub async fn refuse_changed(
    ctx: &Ctx<'_>,
    row: &login_transactions::Model,
    idp_id: Uuid,
) -> AuthnResult<()> {
    let conn = &ctx.state.db;
    tx::take(conn, row.id, row.stage).await?;
    let enabled = idps::find_enabled(conn, ctx.tenant.id, idp_id)
        .await?
        .is_some();
    let reason = if enabled {
        "idp_repointed"
    } else {
        "idp_disabled"
    };
    crate::metrics::login("upstream_failed");
    let details = crate::federation::flow::failure_details(reason, idp_id);
    ctx.audit_sign_in(conn, row.user_id, entity::enums::Outcome::Failure, details)
        .await?;
    Ok(())
}

pub fn decode(raw: &serde_json::Value) -> anyhow::Result<Pending> {
    serde_json::from_value(raw.clone()).context("decoding pending identity")
}

/// The IdP a parked identity may still be linked to: enabled, `link_only`
/// and at the generation the identity was verified at (locked `FOR SHARE`
/// on the caller's transaction).
pub async fn usable_idp(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    pending: &Pending,
) -> anyhow::Result<Option<identity_providers::Model>> {
    Ok(
        idps::lock_current(conn, tenant_id, pending.idp_id, pending.generation)
            .await?
            .filter(|idp| idp.policy == IdpPolicy::LinkOnly),
    )
}

async fn has_identity_at(
    conn: &impl ConnectionTrait,
    user: &users::Model,
    idp_id: Uuid,
) -> anyhow::Result<bool> {
    Ok(user_identities::Entity::find()
        .filter(user_identities::Column::TenantId.eq(user.tenant_id))
        .filter(user_identities::Column::UserId.eq(user.id))
        .filter(user_identities::Column::IdpId.eq(idp_id))
        .one(conn)
        .await
        .context("looking up linked identity")?
        .is_some())
}

/// Called when `user` proved themselves at stage `link`, before the flow
/// goes on: refuses early, with a specific error, what `link_pending` would
/// refuse at the end. An IdP that can no longer link sends the transaction
/// back to the password stage.
pub async fn check(ctx: &Ctx<'_>, tx: &tx::LoadedTx, user: &users::Model) -> AuthnResult<()> {
    let (LoginStage::Link, Some(raw)) = (tx.row.stage, &tx.row.pending_identity) else {
        return Ok(());
    };
    let conn = &ctx.state.db;
    let pending = decode(raw)?;
    let Some(idp) = usable_idp(conn, ctx.tenant.id, &pending).await? else {
        tx::unpark(conn, tx.row.id).await?;
        return Err(AuthnError::LinkUnavailable);
    };
    if has_identity_at(conn, user, idp.id).await? {
        return Err(AuthnError::AlreadyLinked);
    }
    Ok(())
}

/// [`link_pending`] in a savepoint of the completing transaction: when the
/// link can no longer be made (the IdP went away or was repointed, or the
/// identity got linked meanwhile) it is skipped and audited as a failed
/// `user.identity_link`, and the sign-in completes without it.
pub async fn link_or_skip(
    txn: &DatabaseTransaction,
    ctx: &Ctx<'_>,
    pending: &serde_json::Value,
    user: &users::Model,
) -> AuthnResult<()> {
    let savepoint = txn.begin().await?;
    let reason = match link_pending(&savepoint, ctx, pending, user).await {
        Ok(()) => return Ok(savepoint.commit().await?),
        Err(AuthnError::LinkUnavailable) => "link_unavailable",
        Err(AuthnError::AlreadyLinked) => "already_linked",
        Err(other) => return Err(other),
    };
    savepoint.rollback().await?;
    let idp_id = decode(pending)?.idp_id;
    audit::record(
        txn,
        audit::Event {
            tenant_id: ctx.tenant.id,
            actor: audit::Actor::User(Some(user.id)),
            event_type: audit::EventType::UserIdentityLink,
            target: Some(audit::Target::User(user.id)),
            outcome: entity::enums::Outcome::Failure,
            ip: ctx.ip,
            details: json!({ "reason": reason, "idp_id": idp_id, "via": "sign_in" }),
        },
    )
    .await?;
    Ok(())
}

/// Links the identity a link-stage transaction carried, on the transaction
/// that completes the sign-in (`complete::finish`).
pub async fn link_pending(
    txn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    pending: &serde_json::Value,
    user: &users::Model,
) -> AuthnResult<()> {
    let pending = decode(pending)?;
    let Some(idp) = usable_idp(txn, ctx.tenant.id, &pending).await? else {
        return Err(AuthnError::LinkUnavailable);
    };
    let new = NewIdentity {
        tenant_id: ctx.tenant.id,
        user_id: user.id,
        idp_id: idp.id,
        subject: &pending.subject,
        email: pending.email.as_deref(),
    };
    match identities::link(txn, new).await {
        Ok(_) => {}
        Err(LinkError::AlreadyLinked) => return Err(AuthnError::AlreadyLinked),
        Err(LinkError::Internal(err)) => return Err(err.into()),
    }
    let details = json!({ "idp_id": idp.id, "via": "sign_in" });
    audit_user(txn, ctx, user, audit::EventType::UserIdentityLink, details).await?;
    let facts = [("Identity provider", idp.name.clone())];
    notify::event(
        txn,
        &ctx.state.config,
        ctx.tenant,
        user,
        NotifyEvent::IdentityLinked,
        &facts,
    )
    .await?;
    Ok(())
}
