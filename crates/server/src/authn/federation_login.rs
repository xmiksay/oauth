//! The sign-in half of a federation callback: the upstream identity is
//! verified; resolve it to a user (linked, created just in time, or parked
//! for linking) and continue the login transaction.

use std::collections::HashMap;

use anyhow::Context;
use axum::response::Response;
use chrono::Utc;
use entity::{
    enums::{IdpPolicy, LoginStage, Outcome as AuditOutcome},
    identity_providers, user_identities, users,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, TransactionTrait};
use serde_json::json;

use super::{
    AuthnError, AuthnResult, Outcome,
    complete::proceed,
    ctx::Ctx,
    federation::{expired, go, login_url, navigate, reload},
    password::has_second_factor,
    tx::{self, LoadedTx},
};
use crate::{
    audit,
    directory::{self, DirectoryError, NewUser},
    federation::{
        flow,
        id_token::Claims,
        identities::{self, LinkError, NewIdentity, Pending},
        idps,
        policy::{self, Decision, Refusal},
        state::Consumed,
    },
    metrics,
};

enum Resolved {
    Continue(Outcome),
    Refused(Refusal),
    /// Already audited; the user sees `upstream_failed`.
    Failed,
}

pub async fn complete(
    ctx: &Ctx<'_>,
    consumed: Consumed,
    params: &HashMap<String, String>,
) -> anyhow::Result<Response> {
    let tx_id = consumed
        .row
        .tx_id
        .context("login state without transaction")?;
    let tx = match tx::load_at(ctx, &tx_id.to_string(), LoginStage::Password).await {
        Ok(tx) => tx,
        Err(AuthnError::Internal(err)) => return Err(err),
        Err(_) => return Ok(expired(ctx)),
    };
    let back = |code: &str| Ok(go(&login_url(ctx, tx_id, Some(code))));
    let conn = &ctx.state.db;
    let idp = idps::find_enabled(conn, ctx.tenant.id, consumed.row.idp_id).await?;
    let Some(idp) = idp else {
        let details = flow::failure_details("idp_disabled", consumed.row.idp_id);
        ctx.audit_sign_in(conn, None, AuditOutcome::Failure, details)
            .await?;
        return back("upstream_failed");
    };
    // Reconfigured since the round trip began: what comes back answers to
    // the old configuration.
    if idp.generation != consumed.row.idp_generation {
        let details = flow::failure_details("idp_repointed", idp.id);
        ctx.audit_sign_in(conn, None, AuditOutcome::Failure, details)
            .await?;
        return back("upstream_failed");
    }
    let reauth = flow::Reauth::of(&tx.req);
    let finished = flow::finish(ctx.state, &ctx.tenant.slug, &idp, &consumed, params, reauth);
    let claims = match finished.await {
        Ok(claims) => claims,
        Err(failure) => {
            metrics::login("upstream_failed");
            let details = flow::failure_details(failure.0, idp.id);
            ctx.audit_sign_in(conn, None, AuditOutcome::Failure, details)
                .await?;
            return back("upstream_failed");
        }
    };
    match resolve(ctx, tx, &idp, &claims).await {
        Ok(Resolved::Continue(outcome)) => Ok(navigate(ctx, tx_id, outcome)),
        Ok(Resolved::Refused(refusal)) => back(refusal.code()),
        Ok(Resolved::Failed) => back("upstream_failed"),
        Err(AuthnError::AccountDisabled) => back(Refusal::Disabled.code()),
        Err(AuthnError::Internal(err)) => Err(err),
        Err(_) => back("upstream_failed"),
    }
}

async fn resolve(
    ctx: &Ctx<'_>,
    mut tx: LoadedTx,
    idp: &identity_providers::Model,
    claims: &Claims,
) -> AuthnResult<Resolved> {
    let conn = &ctx.state.db;
    let tenant_id = ctx.tenant.id;
    let identity = identities::find(conn, tenant_id, idp.id, &claims.subject).await?;
    let linked = match &identity {
        Some(identity) => Some(
            users::Entity::find_by_id(identity.user_id)
                .filter(users::Column::TenantId.eq(tenant_id))
                .one(conn)
                .await?
                .context("linked user vanished")?,
        ),
        None => None,
    };
    let email = policy::verified_email(claims);
    // Asked only to refuse JIT: an existing account is never matched by email.
    let domain_allowed = email.is_some_and(|e| policy::domain_allowed(&idp.email_domains, e));
    let email_taken = match (&identity, idp.policy, email) {
        (None, IdpPolicy::Jit, Some(_)) if !domain_allowed => false,
        (None, IdpPolicy::Jit, Some(email)) => {
            directory::find_user_by_email(conn, tenant_id, email)
                .await?
                .is_some()
        }
        _ => false,
    };
    let linked_id = linked.as_ref().map(|u| u.id);
    let decision = policy::decide(
        linked.as_ref().map(|u| u.disabled),
        idp.policy,
        email.is_some(),
        domain_allowed,
        email_taken,
    );
    match (decision, identity, linked, email) {
        (Decision::SignIn, Some(identity), Some(user), _) => {
            sign_in(ctx, tx, idp, claims, &identity, user).await
        }
        (Decision::CreateUser, _, _, Some(email)) => jit(ctx, tx, idp, claims, email).await,
        (Decision::PendingLink, ..) => {
            let pending = Pending {
                idp_id: idp.id,
                generation: idp.generation,
                subject: claims.subject.clone(),
                email: claims.email.clone(),
                name: claims.name.clone(),
            };
            let txn = conn.begin().await?;
            if idps::lock_current(&txn, tenant_id, idp.id, idp.generation)
                .await?
                .is_none()
            {
                drop(txn);
                return fail(ctx, idp, "idp_repointed").await;
            }
            tx::to_link(&txn, tx.row.id, &pending).await?;
            txn.commit().await?;
            tx.row.stage = LoginStage::Link;
            Ok(Resolved::Continue(reload()))
        }
        (Decision::Refuse(refusal), ..) => refuse(ctx, idp, linked_id, refusal).await,
        _ => Err(AuthnError::Internal(anyhow::anyhow!(
            "inconsistent federation decision"
        ))),
    }
}

/// Audits a failure (fixed reason); the user sees `upstream_failed`.
async fn fail(
    ctx: &Ctx<'_>,
    idp: &identity_providers::Model,
    reason: &'static str,
) -> AuthnResult<Resolved> {
    metrics::login("upstream_failed");
    let details = flow::failure_details(reason, idp.id);
    ctx.audit_sign_in(&ctx.state.db, None, AuditOutcome::Failure, details)
        .await?;
    Ok(Resolved::Failed)
}

/// Audits a refusal (fixed reason) and reports it to the login page.
async fn refuse(
    ctx: &Ctx<'_>,
    idp: &identity_providers::Model,
    user_id: Option<uuid::Uuid>,
    refusal: Refusal,
) -> AuthnResult<Resolved> {
    if refusal == Refusal::Disabled {
        metrics::login("disabled");
    }
    let details = flow::failure_details(refusal.code(), idp.id);
    ctx.audit_sign_in(&ctx.state.db, user_id, AuditOutcome::Failure, details)
        .await?;
    Ok(Resolved::Refused(refusal))
}

/// Continues as `user`: no local MFA when the upstream's counts, else MFA
/// whenever the user has a factor, then the usual password-change / consent.
async fn continue_as(
    ctx: &Ctx<'_>,
    mut tx: LoadedTx,
    idp: &identity_providers::Model,
    claims: &Claims,
    user: &users::Model,
) -> AuthnResult<Resolved> {
    let trusted = policy::upstream_mfa(idp.trust_upstream_mfa, idp.mfa_acr.as_deref(), claims);
    let next = if !trusted && has_second_factor(ctx.state, ctx.tenant.id, user.id).await? {
        Some(LoginStage::Mfa)
    } else if user.must_change_password {
        Some(LoginStage::ChangePassword)
    } else {
        None
    };
    tx.row.user_id = Some(user.id);
    tx.row.amr = policy::amr(trusted);
    // The upstream's `auth_time` (when it reported one) is when the user
    // authenticated; local `max_age` checks then measure from it.
    let now = Utc::now();
    let auth_time = claims
        .auth_time
        .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
        .unwrap_or(now);
    tx.row.auth_time = Some(auth_time.fixed_offset());
    let via = super::federation_pending::IdpRef {
        idp_id: idp.id,
        generation: idp.generation,
    };
    tx.row.federated = Some(tx::set_federated(&ctx.state.db, tx.row.id, &via).await?);
    let outcome = proceed(ctx, tx, LoginStage::Password, next, user, false).await?;
    Ok(Resolved::Continue(outcome))
}

async fn sign_in(
    ctx: &Ctx<'_>,
    tx: LoadedTx,
    idp: &identity_providers::Model,
    claims: &Claims,
    identity: &user_identities::Model,
    user: users::Model,
) -> AuthnResult<Resolved> {
    let txn = ctx.state.db.begin().await?;
    // Same configuration, and the identity still linked (a repoint unlinks).
    let current = idps::lock_current(&txn, ctx.tenant.id, idp.id, idp.generation).await?;
    if current.is_none() || !identities::touch(&txn, identity, claims.email.as_deref()).await? {
        drop(txn);
        return fail(ctx, idp, "idp_repointed").await;
    }
    txn.commit().await?;
    let user = sync_profile(ctx, user, claims).await?;
    continue_as(ctx, tx, idp, claims, &user).await
}

/// Name fields follow the upstream on every sign-in; the email never does.
async fn sync_profile(
    ctx: &Ctx<'_>,
    user: users::Model,
    claims: &Claims,
) -> anyhow::Result<users::Model> {
    let name = claims
        .name
        .as_deref()
        .and_then(|n| directory::display_name(n, "user").ok());
    let Some(name) = name.filter(|n| *n != user.display_name) else {
        return Ok(user);
    };
    let txn = ctx.state.db.begin().await?;
    let mut row: users::ActiveModel = user.into();
    row.display_name = sea_orm::ActiveValue::Set(name);
    row.updated_at = sea_orm::ActiveValue::Set(Utc::now().fixed_offset());
    let updated = sea_orm::ActiveModelTrait::update(row, &txn).await?;
    audit_user(
        &txn,
        ctx,
        &updated,
        audit::EventType::UserProfileUpdate,
        json!({ "via": "federation", "fields": ["display_name"] }),
    )
    .await?;
    txn.commit().await?;
    Ok(updated)
}

/// Creates the user (no password, verified email, upstream name) and links
/// the identity, atomically.
async fn jit(
    ctx: &Ctx<'_>,
    tx: LoadedTx,
    idp: &identity_providers::Model,
    claims: &Claims,
    email: &str,
) -> AuthnResult<Resolved> {
    let name = claims
        .name
        .as_deref()
        .filter(|n| directory::display_name(n, "user").is_ok())
        .unwrap_or(email);
    let txn = ctx.state.db.begin().await?;
    if idps::lock_current(&txn, ctx.tenant.id, idp.id, idp.generation)
        .await?
        .is_none()
    {
        drop(txn);
        return fail(ctx, idp, "idp_repointed").await;
    }
    let new = NewUser {
        email,
        display_name: name,
        password: None,
        must_change_password: false,
    };
    let mut user = match directory::create_user(&txn, ctx.tenant.id, new).await {
        Ok(user) => user,
        // A concurrent sign-up took the address after `decide` looked.
        Err(DirectoryError::EmailTaken(_)) => {
            drop(txn);
            return refuse(ctx, idp, None, Refusal::EmailTaken).await;
        }
        Err(DirectoryError::Invalid(_)) => {
            drop(txn);
            return fail(ctx, idp, "jit_invalid_email").await;
        }
        Err(other) => return Err(other.into()),
    };
    users::Entity::update_many()
        .col_expr(
            users::Column::EmailVerified,
            sea_orm::sea_query::Expr::value(true),
        )
        .filter(users::Column::Id.eq(user.id))
        .exec(&txn)
        .await?;
    user.email_verified = true;
    let new = NewIdentity {
        tenant_id: ctx.tenant.id,
        user_id: user.id,
        idp_id: idp.id,
        subject: &claims.subject,
        email: Some(email),
    };
    match identities::link(&txn, new).await {
        Ok(_) => {}
        Err(LinkError::AlreadyLinked) => return Err(AuthnError::WrongStep),
        Err(LinkError::Internal(err)) => return Err(err.into()),
    }
    let details = json!({ "via": "federation", "idp_id": idp.id, "email": user.email });
    audit_user(&txn, ctx, &user, audit::EventType::UserCreate, details).await?;
    txn.commit().await?;
    continue_as(ctx, tx, idp, claims, &user).await
}

pub(super) async fn audit_user(
    conn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    user: &users::Model,
    event_type: audit::EventType,
    details: serde_json::Value,
) -> anyhow::Result<()> {
    audit::record(
        conn,
        audit::Event {
            tenant_id: ctx.tenant.id,
            actor: audit::Actor::User(Some(user.id)),
            event_type,
            target: Some(audit::Target::User(user.id)),
            outcome: AuditOutcome::Success,
            ip: ctx.ip,
            details,
        },
    )
    .await
}
