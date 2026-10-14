//! `/api/v1/me…` — the signed-in user's own account (My Account).
//! Any user of the tenant with a delegated token carrying
//! `Directory.AccessAsUser`; no directory role needed.

use axum::{extract::State, http::StatusCode};
use entity::{applications, consent_grants, sessions, users};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
    TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller, consents,
    extract::{Json, Path},
    guard::find_user,
    set_changed,
    user_actions::{list_sessions, session_view},
    users::detailed_view,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authn::rate_limit,
    directory::{self, display_name, password},
    error::{AppError, AppResult},
    tokens::refresh,
};

/// The caller's user row (a token can outlive nothing: disabled / deleted
/// users already fail authentication).
pub async fn me(state: &AppState, caller: &Caller) -> AppResult<users::Model> {
    find_user(&state.db, caller.tenant_id(), caller.user_id()?).await
}

/// Re-authentication for sensitive self-service changes: rate-limited like
/// sign-in (the bucket is shared with the login API), 403 when wrong.
pub async fn verify_password(
    state: &AppState,
    user: &users::Model,
    candidate: &str,
) -> AppResult<()> {
    let key = rate_limit::user_key(user.id);
    let now = chrono::Utc::now();
    if let Err(retry_after) = rate_limit::hit(
        &state.db,
        user.tenant_id,
        &key,
        rate_limit::PER_ACCOUNT,
        now,
    )
    .await?
    {
        return Err(AppError::RateLimited { retry_after });
    }
    let ok = match &user.password_hash {
        Some(phc) if candidate.len() <= password::MAX_PASSWORD_LEN * 4 => {
            password::verify(candidate, phc).await?
        }
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "the current password is incorrect".into(),
        ))
    }
}

pub async fn get(State(state): State<AppState>, caller: Caller) -> AppResult<axum::Json<Value>> {
    let user = me(&state, &caller).await?;
    Ok(axum::Json(detailed_view(&state.db, &user).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateMe {
    display_name: String,
}

pub async fn update(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<UpdateMe>,
) -> AppResult<axum::Json<Value>> {
    let user = me(&state, &caller).await?;
    let mut row: users::ActiveModel = user.clone().into();
    if !set_changed(
        &mut row.display_name,
        display_name(&body.display_name, "user")?,
    ) {
        return Ok(axum::Json(detailed_view(&state.db, &user).await?));
    }
    row.updated_at = Set(chrono::Utc::now().fixed_offset());
    let txn = state.db.begin().await?;
    let updated = row.update(&txn).await?;
    caller
        .audit(
            &txn,
            EventType::UserProfileUpdate,
            Some(Target::User(user.id)),
            json!({ "fields": ["display_name"] }),
        )
        .await?;
    txn.commit().await?;
    Ok(axum::Json(detailed_view(&state.db, &updated).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePassword {
    current_password: String,
    new_password: String,
}

/// Signs the user out of every OTHER session (sessions, refresh tokens,
/// opaque access tokens); the session the calling token belongs to, with
/// its refresh tokens, survives so the SPA keeps working.
pub async fn change_password(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<ChangePassword>,
) -> AppResult<StatusCode> {
    let user = me(&state, &caller).await?;
    verify_password(&state, &user, &body.current_password).await?;
    password::validate(&body.new_password)?;
    if body.new_password == body.current_password {
        return Err(AppError::BadRequest(
            "the new password must differ from the current one".into(),
        ));
    }
    let txn = state.db.begin().await?;
    directory::set_password_keeping(
        &txn,
        user.tenant_id,
        user.id,
        &body.new_password,
        false,
        caller.session_id,
    )
    .await?;
    caller
        .audit(
            &txn,
            EventType::UserPasswordChange,
            Some(Target::User(user.id)),
            json!({ "via": "me" }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn sessions(
    State(state): State<AppState>,
    caller: Caller,
) -> AppResult<axum::Json<Value>> {
    let user_id = caller.user_id()?;
    let items: Vec<Value> = list_sessions(&state.db, caller.tenant_id(), user_id)
        .await?
        .iter()
        .map(|s| session_view(s, caller.session_id))
        .collect();
    Ok(axum::Json(json!({ "items": items })))
}

/// Signs one device out: deletes the session and revokes the refresh
/// tokens (and their opaque access tokens) issued in it.
pub async fn revoke_session(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    let user_id = caller.user_id()?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    let removed = sessions::Entity::delete_many()
        .filter(sessions::Column::TenantId.eq(tenant_id))
        .filter(sessions::Column::UserId.eq(user_id))
        .filter(sessions::Column::Id.eq(id))
        .exec(&txn)
        .await?;
    if removed.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    refresh::revoke_by_session(&txn, tenant_id, id).await?;
    caller
        .audit(
            &txn,
            EventType::UserSessionRevoke,
            Some(Target::User(user_id)),
            json!({ "session_id": id }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Signs out everywhere (sessions, refresh tokens, opaque access tokens).
pub async fn revoke_all_sessions(
    State(state): State<AppState>,
    caller: Caller,
) -> AppResult<StatusCode> {
    let user_id = caller.user_id()?;
    let txn = state.db.begin().await?;
    directory::revoke_credentials(&txn, caller.tenant_id(), user_id, None).await?;
    caller
        .audit(
            &txn,
            EventType::UserSessionsRevoke,
            Some(Target::User(user_id)),
            json!({ "via": "me" }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

fn app_summary(apps: &[applications::Model], id: Uuid) -> Value {
    apps.iter().find(|a| a.id == id).map_or(
        Value::Null,
        |a| json!({ "id": a.id, "client_id": a.client_id, "display_name": a.display_name }),
    )
}

/// The user's own consent grants (tenant-wide admin grants are not theirs
/// to revoke and are not listed).
pub async fn consents(
    State(state): State<AppState>,
    caller: Caller,
) -> AppResult<axum::Json<Value>> {
    let user_id = caller.user_id()?;
    let conn = &state.db;
    let grants = consent_grants::Entity::find()
        .filter(consent_grants::Column::TenantId.eq(caller.tenant_id()))
        .filter(consent_grants::Column::UserId.eq(user_id))
        .order_by_asc(consent_grants::Column::Id)
        .all(conn)
        .await?;
    let ids = grants
        .iter()
        .flat_map(|g| [g.client_application_id, g.resource_application_id]);
    let apps = applications::Entity::find()
        .filter(applications::Column::Id.is_in(ids))
        .all(conn)
        .await?;
    let items: Vec<Value> = grants
        .iter()
        .map(|g| {
            let mut v = consents::view(g);
            if let Some(obj) = v.as_object_mut() {
                obj.insert("client".into(), app_summary(&apps, g.client_application_id));
                obj.insert(
                    "resource".into(),
                    app_summary(&apps, g.resource_application_id),
                );
            }
            v
        })
        .collect();
    Ok(axum::Json(json!({ "items": items })))
}

pub async fn revoke_consent(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    let user_id = caller.user_id()?;
    let txn = state.db.begin().await?;
    let grant = consent_grants::Entity::find_by_id(id)
        .filter(consent_grants::Column::TenantId.eq(caller.tenant_id()))
        .filter(consent_grants::Column::UserId.eq(user_id))
        .one(&txn)
        .await?
        .ok_or(AppError::NotFound)?;
    consents::delete_and_revoke(&txn, &grant).await?;
    caller
        .audit(
            &txn,
            EventType::ConsentRevoke,
            Some(Target::ConsentGrant(id)),
            json!({ "scopes": grant.scopes, "user_id": user_id, "via": "me" }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
