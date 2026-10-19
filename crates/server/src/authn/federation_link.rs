//! The My Account half of a federation callback: a signed-in user (who
//! re-authenticated in `POST me/identities/{idp}/link`) comes back from the
//! provider; link the verified identity to them.

use std::collections::HashMap;

use anyhow::Context;
use axum::response::Response;
use entity::{
    enums::{NotifyEvent, Outcome as AuditOutcome},
    sessions, users,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, TransactionTrait,
};
use serde_json::json;
use uuid::Uuid;

use super::{ctx::Ctx, federation::go};
use crate::{
    audit,
    federation::{
        flow,
        identities::{self, LinkError, NewIdentity},
        idps,
        state::Consumed,
    },
    notify,
};

fn back(ctx: &Ctx<'_>, query: &str) -> Response {
    let origin = ctx.state.config.tenant_origin(&ctx.tenant.slug);
    go(&format!("{origin}/myaccount/security?{query}"))
}

async fn record(
    conn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    user_id: Uuid,
    outcome: AuditOutcome,
    details: serde_json::Value,
) -> anyhow::Result<()> {
    audit::record(
        conn,
        audit::Event {
            tenant_id: ctx.tenant.id,
            actor: audit::Actor::User(Some(user_id)),
            event_type: audit::EventType::UserIdentityLink,
            target: Some(audit::Target::User(user_id)),
            outcome,
            ip: ctx.ip,
            details,
        },
    )
    .await
}

/// The delegated session that started the link is unexpired and the
/// user's, locked `FOR SHARE` on `conn`'s transaction (if any).
async fn session_live(
    conn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    session_id: Option<Uuid>,
    user_id: Uuid,
) -> anyhow::Result<bool> {
    let Some(id) = session_id else {
        return Ok(false);
    };
    let now = chrono::Utc::now().fixed_offset();
    Ok(sessions::Entity::find_by_id(id)
        .filter(sessions::Column::TenantId.eq(ctx.tenant.id))
        .lock_shared()
        .one(conn)
        .await?
        .is_some_and(|s| s.user_id == user_id && s.expires_at > now))
}

pub async fn complete(
    ctx: &Ctx<'_>,
    consumed: Consumed,
    params: &HashMap<String, String>,
) -> anyhow::Result<Response> {
    let user_id = consumed.row.user_id.context("link state without user")?;
    let conn = &ctx.state.db;
    let failed = "federation_error=upstream_failed";
    let user = users::Entity::find_by_id(user_id)
        .filter(users::Column::TenantId.eq(ctx.tenant.id))
        .one(conn)
        .await?;
    let Some(user) = user else {
        return Ok(back(ctx, failed));
    };
    if user.disabled {
        return Ok(back(ctx, "federation_error=account_disabled"));
    }
    // The signed-in session that asked for the link must still be live: a
    // sign-out (or a revocation after a stolen token) in between cancels it.
    if !session_live(conn, ctx, consumed.row.session_id, user.id).await? {
        let details = flow::failure_details("session_ended", consumed.row.idp_id);
        record(conn, ctx, user.id, AuditOutcome::Failure, details).await?;
        return Ok(back(ctx, "federation_error=session_ended"));
    }
    let idp_id = consumed.row.idp_id;
    let Some(idp) = idps::find_enabled(conn, ctx.tenant.id, idp_id).await? else {
        let details = flow::failure_details("idp_disabled", idp_id);
        record(conn, ctx, user.id, AuditOutcome::Failure, details).await?;
        return Ok(back(ctx, failed));
    };
    if idp.generation != consumed.row.idp_generation {
        let details = flow::failure_details("idp_repointed", idp_id);
        record(conn, ctx, user.id, AuditOutcome::Failure, details).await?;
        return Ok(back(ctx, failed));
    }
    let claims = match flow::finish(
        ctx.state,
        &ctx.tenant.slug,
        &idp,
        &consumed,
        params,
        flow::Reauth::default(),
    )
    .await
    {
        Ok(claims) => claims,
        Err(failure) => {
            let details = flow::failure_details(failure.0, idp.id);
            record(conn, ctx, user.id, AuditOutcome::Failure, details).await?;
            return Ok(back(ctx, failed));
        }
    };
    let txn = conn.begin().await?;
    // Checked again where the link is written, with both rows locked: the
    // session may have been revoked, or the IdP repointed, during the
    // upstream exchange.
    let current = idps::lock_current(&txn, ctx.tenant.id, idp.id, idp.generation).await?;
    if current.is_none() {
        drop(txn);
        let details = flow::failure_details("idp_repointed", idp.id);
        record(conn, ctx, user.id, AuditOutcome::Failure, details).await?;
        return Ok(back(ctx, failed));
    }
    // IdP → user → session: an admin's revoke / disable locks the user row
    // FOR UPDATE and then deletes the sessions, so taking the user before the
    // session keeps the two from deadlocking. A user disabled meanwhile is
    // refused like an ended session.
    let user_ok = users::Entity::find_by_id(user.id)
        .filter(users::Column::TenantId.eq(ctx.tenant.id))
        .lock_shared()
        .one(&txn)
        .await?
        .is_some_and(|u| !u.disabled);
    if !user_ok || !session_live(&txn, ctx, consumed.row.session_id, user.id).await? {
        drop(txn);
        let details = flow::failure_details("session_ended", idp.id);
        record(conn, ctx, user.id, AuditOutcome::Failure, details).await?;
        return Ok(back(ctx, "federation_error=session_ended"));
    }
    let new = NewIdentity {
        tenant_id: ctx.tenant.id,
        user_id: user.id,
        idp_id: idp.id,
        subject: &claims.subject,
        email: claims.email.as_deref(),
    };
    match identities::link(&txn, new).await {
        Ok(_) => {}
        Err(LinkError::AlreadyLinked) => {
            drop(txn);
            let details = flow::failure_details("already_linked", idp.id);
            record(conn, ctx, user.id, AuditOutcome::Failure, details).await?;
            return Ok(back(ctx, "federation_error=already_linked"));
        }
        Err(LinkError::Internal(err)) => return Err(err),
    }
    let details = json!({ "idp_id": idp.id, "via": "me" });
    record(&txn, ctx, user.id, AuditOutcome::Success, details).await?;
    let facts = [("Identity provider", idp.name.clone())];
    notify::event(
        &txn,
        &ctx.state.config,
        ctx.tenant,
        &user,
        NotifyEvent::IdentityLinked,
        &facts,
    )
    .await?;
    txn.commit().await?;
    Ok(back(ctx, "federation=linked"))
}
