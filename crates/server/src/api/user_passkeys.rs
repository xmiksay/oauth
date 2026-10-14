//! `users/{id}/passkeys…` — an administrator's view of a user's passkeys.
//! Removal follows the same last-sign-in-method rule as self-service.

use axum::{extract::State, http::StatusCode};
use sea_orm::TransactionTrait;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    extract::Path,
    guard::{ensure_can_modify_user, find_user, lock_user},
    me_mfa::mfa_notice,
    me_passkeys::passkey_error,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    error::{AppError, AppResult},
    passkey::{store, wire::view},
};

pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Directory, Access::Read)?;
    let user = find_user(&state.db, caller.tenant_id(), id).await?;
    let items: Vec<Value> = store::list(&state.db, user.tenant_id, user.id)
        .await?
        .iter()
        .map(view)
        .collect();
    Ok(axum::Json(json!({ "items": items })))
}

pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path((id, passkey_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    caller.require(Area::Directory, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    let user = lock_user(&txn, tenant_id, id).await?;
    ensure_can_modify_user(&txn, &caller, id).await?;
    let credential = store::find_for_user(&txn, tenant_id, id, passkey_id)
        .await?
        .ok_or(AppError::NotFound)?;
    store::remove(&txn, &user, &credential)
        .await
        .map_err(passkey_error)?;
    let details = json!({ "passkey_id": passkey_id, "name": credential.name, "via": "admin" });
    caller
        .audit(
            &txn,
            EventType::MfaPasskeyRemove,
            Some(Target::User(id)),
            details,
        )
        .await?;
    mfa_notice(
        &state,
        &caller,
        &txn,
        &user,
        "passkey removed by an administrator",
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
