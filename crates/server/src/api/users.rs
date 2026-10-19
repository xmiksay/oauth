//! `/api/v1/users` CRUD.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::{enums::EmailTokenPurpose, user_recovery_codes, user_totp, users};
use sea_orm::{
    ActiveEnum, ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait,
    QueryFilter, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    auth::directory_roles,
    extract::{Json, Path, Query},
    guard::{ensure_can_modify_user, ensure_not_last_global_admin, find_user},
    page::{self, Order, PageParams, Paged},
    search, ts,
    user_actions::ChosenPassword,
    user_invite::{email_replaced, require_email, send_invite},
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    directory::{self, DirectoryError, NewUser, display_name, normalize_email},
    error::{AppError, AppResult},
    mail::links,
    passkey, telegram,
};

pub fn view(u: &users::Model) -> Value {
    json!({
        "id": u.id,
        "email": u.email,
        "display_name": u.display_name,
        "user_type": u.user_type.to_value(),
        "email_verified": u.email_verified,
        "disabled": u.disabled,
        "must_change_password": u.must_change_password,
        "has_password": u.password_hash.is_some(),
        "created_at": ts(&u.created_at),
        "updated_at": ts(&u.updated_at),
    })
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    page: PageParams,
    search: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    Query(q): Query<ListQuery>,
) -> AppResult<Paged<Value>> {
    caller.require(Area::Directory, Access::Read)?;
    let mut select = users::Entity::find().filter(users::Column::TenantId.eq(caller.tenant_id()));
    if let Some(cond) = search(
        q.search.as_deref(),
        &[users::Column::Email, users::Column::DisplayName],
    )? {
        select = select.filter(cond);
    }
    let page = page::fetch(
        &state.db,
        select,
        users::Column::Id,
        q.page.parse()?,
        Order::Ascending,
        |u| u.id,
    )
    .await?;
    Ok(page.map(|u| view(&u)))
}

/// A single user, with directory roles and MFA state.
pub async fn get(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Directory, Access::Read)?;
    let conn = &state.db;
    let user = find_user(conn, caller.tenant_id(), id).await?;
    let mut out = detailed_view(conn, &user).await?;
    let identities = super::user_identities::list_view(conn, &user, true).await?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("identities".into(), json!(identities));
    }
    Ok(axum::Json(out))
}

/// [`view`] plus `directory_roles` and `mfa` (also served by `GET me`).
pub async fn detailed_view(
    conn: &impl sea_orm::ConnectionTrait,
    user: &users::Model,
) -> AppResult<Value> {
    let roles: Vec<String> = directory_roles(conn, user.tenant_id, user.id)
        .await?
        .into_iter()
        .map(|r| r.to_value())
        .collect();
    let totp = user_totp::Entity::find_by_id(user.id)
        .filter(user_totp::Column::TenantId.eq(user.tenant_id))
        .one(conn)
        .await?;
    let recovery_left = user_recovery_codes::Entity::find()
        .filter(user_recovery_codes::Column::TenantId.eq(user.tenant_id))
        .filter(user_recovery_codes::Column::UserId.eq(user.id))
        .filter(user_recovery_codes::Column::UsedAt.is_null())
        .count(conn)
        .await?;
    let passkeys = passkey::store::count(conn, user.tenant_id, user.id).await?;
    let telegram = telegram::links::find(conn, user.tenant_id, user.id)
        .await?
        .is_some();
    let mut out = view(user);
    if let Some(obj) = out.as_object_mut() {
        obj.insert("directory_roles".into(), json!(roles));
        obj.insert(
            "mfa".into(),
            json!({
                "totp": totp.as_ref().is_some_and(|t| t.confirmed_at.is_some()),
                "totp_pending": totp.as_ref().is_some_and(|t| t.confirmed_at.is_none()),
                "recovery_codes_remaining": recovery_left,
                "passkeys": passkeys,
                "telegram": telegram,
            }),
        );
    }
    Ok(out)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUser {
    email: String,
    display_name: String,
    /// Omitted: a one-time password is generated and returned.
    password: Option<String>,
    /// Defaults to `true` (change at first sign-in).
    must_change_password: Option<bool>,
    /// Create without a password and email an invitation link instead
    /// (needs SMTP; excludes `password` / `must_change_password`).
    invite: Option<bool>,
}

pub async fn create(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<CreateUser>,
) -> AppResult<Response> {
    caller.require(Area::Directory, Access::Write)?;
    let invite = body.invite == Some(true);
    if invite {
        if body.password.is_some() || body.must_change_password.is_some() {
            return Err(AppError::BadRequest(
                "an invitation sets no password: omit password and must_change_password".into(),
            ));
        }
        require_email(&state)?;
    }
    let chosen = (!invite)
        .then(|| ChosenPassword::new(body.password, body.must_change_password))
        .transpose()?;
    let txn = state.db.begin().await?;
    let user = directory::create_user(
        &txn,
        caller.tenant_id(),
        NewUser {
            email: &body.email,
            display_name: &body.display_name,
            password: chosen.as_ref().map(|c| c.value.as_str()),
            must_change_password: chosen.as_ref().is_some_and(|c| c.must_change),
        },
    )
    .await?;
    let how = match &chosen {
        None => "invite",
        Some(c) if c.generated => "generated",
        Some(_) => "set_by_admin",
    };
    let details = json!({ "email": user.email, "password": how });
    caller
        .audit(
            &txn,
            EventType::UserCreate,
            Some(Target::User(user.id)),
            details,
        )
        .await?;
    if invite {
        send_invite(&state, &caller, &txn, &user, false).await?;
    } else if state.config.email_enabled() {
        let tenant = &caller.tenant;
        links::send(
            &txn,
            &state.config,
            tenant,
            &user,
            EmailTokenPurpose::Verify,
            None,
        )
        .await?;
    }
    txn.commit().await?;
    let body = json!({
        "user": view(&user),
        "one_time_password": chosen.as_ref().and_then(ChosenPassword::one_time),
        "invite_sent": invite,
    });
    Ok((StatusCode::CREATED, axum::Json(body)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateUser {
    display_name: Option<String>,
    email: Option<String>,
    disabled: Option<bool>,
}

pub async fn update(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateUser>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Directory, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    let user = find_user(&txn, tenant_id, id).await?;
    ensure_can_modify_user(&txn, &caller, id).await?;
    let mut row: users::ActiveModel = user.clone().into();
    let mut fields = Vec::new();
    if let Some(name) = &body.display_name {
        let name = display_name(name, "user")?;
        if name != user.display_name {
            row.display_name = Set(name);
            fields.push("display_name");
        }
    }
    if let Some(email) = &body.email {
        let email = normalize_email(email)?;
        if email != user.email {
            row.email = Set(email);
            // The new address is unproven until its owner opens a link.
            row.email_verified = Set(false);
            fields.push("email");
        }
    }
    let disabling = body.disabled == Some(true) && !user.disabled;
    if let Some(disabled) = body.disabled.filter(|d| *d != user.disabled) {
        if disabling {
            ensure_not_last_global_admin(&txn, tenant_id, id).await?;
        }
        row.disabled = Set(disabled);
        fields.push("disabled");
    }
    if fields.is_empty() {
        return Ok(axum::Json(view(&user)));
    }
    row.updated_at = Set(chrono::Utc::now().fixed_offset());
    let updated = row.update(&txn).await.map_err(|err| {
        if directory::violates_unique(&err, "users_tenant_email") {
            AppError::from(DirectoryError::EmailTaken(
                body.email.clone().unwrap_or_default(),
            ))
        } else {
            err.into()
        }
    })?;
    if disabling {
        // A disabled account keeps no live sessions or refresh tokens.
        directory::revoke_credentials(&txn, tenant_id, id, None).await?;
    }
    if updated.email != user.email {
        email_replaced(&state, &caller, &txn, &updated, &user).await?;
    }
    let details = json!({ "fields": fields, "disabled": updated.disabled });
    caller
        .audit(&txn, EventType::UserUpdate, Some(Target::User(id)), details)
        .await?;
    txn.commit().await?;
    Ok(axum::Json(view(&updated)))
}

pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    caller.require(Area::Directory, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    let user = find_user(&txn, tenant_id, id).await?;
    ensure_can_modify_user(&txn, &caller, id).await?;
    ensure_not_last_global_admin(&txn, tenant_id, id).await?;
    // Sessions, tokens, memberships, roles and grants cascade.
    users::Entity::delete_by_id(id).exec(&txn).await?;
    caller
        .audit(
            &txn,
            EventType::UserDelete,
            Some(Target::User(id)),
            json!({ "email": user.email }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
