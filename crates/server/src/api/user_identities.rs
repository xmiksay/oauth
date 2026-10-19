//! Linked upstream identities: their JSON view (admin and self-service),
//! the unlink both share, and `DELETE users/{id}/identities/{identity}`.

use axum::{extract::State, http::StatusCode};
use entity::{user_identities, users};
use sea_orm::{ConnectionTrait, EntityTrait, TransactionTrait};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    extract::Path,
    guard::{ensure_can_modify_user, lock_user},
    ts,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    error::{AppError, AppResult},
    federation::{identities, idps},
};

/// `subject` only for administrators (`admin`): users know who they are.
pub fn view(identity: &user_identities::Model, idp_name: &str, admin: bool) -> Value {
    let mut out = json!({
        "id": identity.id,
        "idp_id": identity.idp_id,
        "idp_name": idp_name,
        "email": identity.email,
        "linked_at": ts(&identity.linked_at),
        "last_used_at": identity.last_used_at.as_ref().map(ts),
    });
    if admin && let Some(obj) = out.as_object_mut() {
        obj.insert("subject".into(), json!(identity.subject));
    }
    out
}

pub async fn list_view(
    conn: &impl ConnectionTrait,
    user: &users::Model,
    admin: bool,
) -> AppResult<Vec<Value>> {
    Ok(identities::list(conn, user.tenant_id, user.id)
        .await?
        .iter()
        .map(|(identity, name)| view(identity, name, admin))
        .collect())
}

/// Removes `identity_id` of `user` (row-locked by the caller), refusing to
/// take the user's last sign-in method; audits it. Returns `NotFound` for
/// another user's identity.
pub async fn unlink(
    conn: &impl ConnectionTrait,
    caller: &Caller,
    user: &users::Model,
    identity_id: Uuid,
    via: &str,
) -> AppResult<()> {
    let identity = identities::find_for_user(conn, user.tenant_id, user.id, identity_id)
        .await?
        .ok_or(AppError::NotFound)?;
    // An identity at a disabled IdP signs nobody in: removing it changes
    // nothing about the user's ways in.
    let usable = idps::find_enabled(conn, user.tenant_id, identity.idp_id)
        .await?
        .is_some();
    if usable && !identities::methods(conn, user).await?.can_drop_identity() {
        return Err(AppError::Conflict(
            "the last sign-in method can't be removed: set a password or add a passkey first"
                .into(),
        ));
    }
    user_identities::Entity::delete_by_id(identity.id)
        .exec(conn)
        .await?;
    caller
        .audit(
            conn,
            EventType::UserIdentityUnlink,
            Some(Target::User(user.id)),
            json!({ "identity_id": identity.id, "idp_id": identity.idp_id, "via": via }),
        )
        .await
}

pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path((id, identity_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    caller.require(Area::Directory, Access::Write)?;
    let txn = state.db.begin().await?;
    let user = lock_user(&txn, caller.tenant_id(), id).await?;
    ensure_can_modify_user(&txn, &caller, id).await?;
    unlink(&txn, &caller, &user, identity_id, "admin").await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
