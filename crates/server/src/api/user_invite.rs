//! Invitations (`POST users` with `invite: true`, `POST users/{id}/invite`)
//! and the email side of an admin changing a user's address.

use axum::{extract::State, http::StatusCode};
use entity::{enums::EmailTokenPurpose, users};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde_json::json;
use uuid::Uuid;

use super::{
    Caller,
    extract::Path,
    guard::{ensure_can_modify_user, lock_user},
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    error::{AppError, AppResult},
    mail::{links, tokens},
    notify,
};

/// 400 unless the server can send email.
pub fn require_email(state: &AppState) -> AppResult<()> {
    if state.config.email_enabled() {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "email delivery is not configured on this server".into(),
        ))
    }
}

/// Mails a 7-day invitation link (voiding any earlier one) and audits it.
pub async fn send_invite(
    state: &AppState,
    caller: &Caller,
    conn: &impl ConnectionTrait,
    user: &users::Model,
    resend: bool,
) -> AppResult<()> {
    let purpose = EmailTokenPurpose::Invite;
    links::send(conn, &state.config, &caller.tenant, user, purpose, None).await?;
    caller
        .audit(
            conn,
            EventType::UserInvite,
            Some(Target::User(user.id)),
            json!({ "email": user.email, "resend": resend }),
        )
        .await
}

/// After an admin changed `before`'s address (now `user.email`): links sent
/// to the old address die; the new one gets a verification link — or, for
/// a user who never set a password, a fresh invitation (the old one went to
/// the old address) — and the old one a notice if it was verified.
pub async fn email_replaced(
    state: &AppState,
    caller: &Caller,
    conn: &impl ConnectionTrait,
    user: &users::Model,
    before: &users::Model,
) -> AppResult<()> {
    tokens::invalidate(conn, user.tenant_id, user.id, &tokens::ALL).await?;
    if state.config.email_enabled() {
        if user.password_hash.is_none() {
            send_invite(state, caller, conn, user, true).await?;
        } else {
            let purpose = EmailTokenPurpose::Verify;
            links::send(conn, &state.config, &caller.tenant, user, purpose, None).await?;
        }
    }
    let old = notify::OldAddress {
        email: &before.email,
        verified: before.email_verified,
    };
    notify::email_changed(conn, &state.config, &caller.tenant, user, old).await?;
    Ok(())
}

/// Re-sends the invitation of a user who has not set a password yet.
pub async fn resend(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    caller.require(Area::Directory, Access::Write)?;
    require_email(&state)?;
    let txn = state.db.begin().await?;
    // Locked: a concurrent invite acceptance can't slip between the check
    // and the new link.
    let user = lock_user(&txn, caller.tenant_id(), id).await?;
    ensure_can_modify_user(&txn, &caller, id).await?;
    if user.password_hash.is_some() {
        return Err(AppError::Conflict(
            "the user already has a password; use a password reset instead".into(),
        ));
    }
    send_invite(&state, &caller, &txn, &user, true).await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
