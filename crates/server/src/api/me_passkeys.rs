//! `me/passkeys…` — the signed-in user's passkeys: list, register (after
//! re-authentication), rename, remove (re-authenticated; never the last
//! sign-in method).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::enums::WebauthnPurpose;
use sea_orm::TransactionTrait;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    extract::{Json, Path},
    guard::lock_user,
    me::me,
    me_mfa::mfa_notice,
    reauth::ReauthBody,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    error::{AppError, AppResult},
    passkey::{
        self, PasskeyError, RegistrationJson, Scope,
        store::{self, NewCredential},
        wire::view,
    },
};

/// Registration and removal failures as management-API errors (a
/// rejected credential is never explained beyond "could not register").
pub fn passkey_error(err: PasskeyError) -> AppError {
    match err {
        PasskeyError::Internal(err) => AppError::Internal(err),
        PasskeyError::Conflict(msg) => AppError::Conflict(msg.into()),
        PasskeyError::Invalid(msg) => AppError::BadRequest(msg.into()),
        _ => AppError::BadRequest("the passkey could not be registered".into()),
    }
}

pub async fn list(State(state): State<AppState>, caller: Caller) -> AppResult<axum::Json<Value>> {
    let user_id = caller.user_id()?;
    let items: Vec<Value> = store::list(&state.db, caller.tenant_id(), user_id)
        .await?
        .iter()
        .map(view)
        .collect();
    Ok(axum::Json(json!({ "items": items })))
}

/// `POST me/passkeys/options`: creation options after re-authentication.
pub async fn begin(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<ReauthBody>,
) -> AppResult<axum::Json<Value>> {
    let user = me(&state, &caller).await?;
    let existing = store::list(&state.db, user.tenant_id, user.id).await?;
    // Refused before the browser creates anything: a credential made for
    // options that `finish` then rejects is orphaned on the authenticator.
    if existing.len() as u64 >= store::MAX_PER_USER {
        return Err(AppError::Conflict(
            "the maximum number of passkeys is reached".into(),
        ));
    }
    body.verify(&state, &caller, &user).await?;
    let handle = store::ensure_handle(&state.db, &user).await?;
    let scope = Scope::User {
        purpose: WebauthnPurpose::Register,
        user_id: user.id,
    };
    let challenge = passkey::challenge::issue(&state.db, user.tenant_id, scope).await?;
    let rp = passkey::rp(&state.config, &caller.tenant.slug);
    Ok(axum::Json(passkey::wire::creation_options(
        &rp,
        &caller.tenant.display_name,
        &user,
        &handle,
        &challenge,
        &existing,
    )))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finish {
    credential: RegistrationJson,
    name: Option<String>,
}

/// `POST me/passkeys`: stores the credential answering the challenge of
/// `begin` (which is where re-authentication happened).
pub async fn finish(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<Finish>,
) -> AppResult<Response> {
    let user_id = caller.user_id()?;
    let tenant_id = caller.tenant_id();
    let registration = body
        .credential
        .decode()
        .map_err(|_| AppError::BadRequest("malformed passkey response".into()))?;
    let name = store::name(body.name.as_deref()).map_err(passkey_error)?;
    let rp = passkey::rp(&state.config, &caller.tenant.slug);
    let registered =
        passkey::verify_registration(&state.db, &rp, tenant_id, user_id, &registration)
            .await
            .map_err(passkey_error)?;
    let txn = state.db.begin().await?;
    let user = lock_user(&txn, tenant_id, user_id).await?;
    let credential = store::insert(
        &txn,
        NewCredential {
            tenant_id,
            user_id,
            rp_id: &rp.id,
            registered: &registered,
            transports: registration.transports,
            name,
        },
    )
    .await
    .map_err(passkey_error)?;
    let details = json!({ "passkey_id": credential.id, "name": credential.name, "via": "me" });
    caller
        .audit(
            &txn,
            EventType::MfaPasskeyRegister,
            Some(Target::User(user_id)),
            details,
        )
        .await?;
    mfa_notice(&state, &caller, &txn, &user, "passkey added").await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, axum::Json(view(&credential))).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rename {
    name: String,
}

pub async fn rename(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
    Json(body): Json<Rename>,
) -> AppResult<axum::Json<Value>> {
    let user_id = caller.user_id()?;
    let name = store::name(Some(&body.name)).map_err(passkey_error)?;
    let txn = state.db.begin().await?;
    let credential = store::find_for_user(&txn, caller.tenant_id(), user_id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if credential.name == name {
        return Ok(axum::Json(view(&credential)));
    }
    let renamed = store::rename(&txn, &credential, &name).await?;
    let details = json!({ "passkey_id": id, "name": name, "via": "me" });
    caller
        .audit(
            &txn,
            EventType::MfaPasskeyRename,
            Some(Target::User(user_id)),
            details,
        )
        .await?;
    txn.commit().await?;
    Ok(axum::Json(view(&renamed)))
}

pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
    Json(body): Json<ReauthBody>,
) -> AppResult<StatusCode> {
    let user = me(&state, &caller).await?;
    let tenant_id = user.tenant_id;
    if store::find_for_user(&state.db, tenant_id, user.id, id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound);
    }
    body.verify(&state, &caller, &user).await?;
    let txn = state.db.begin().await?;
    let user = lock_user(&txn, tenant_id, user.id).await?;
    let credential = store::find_for_user(&txn, tenant_id, user.id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    store::remove(&txn, &user, &credential)
        .await
        .map_err(passkey_error)?;
    let details = json!({ "passkey_id": id, "name": credential.name, "via": "me" });
    caller
        .audit(
            &txn,
            EventType::MfaPasskeyRemove,
            Some(Target::User(user.id)),
            details,
        )
        .await?;
    mfa_notice(&state, &caller, &txn, &user, "passkey removed").await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
