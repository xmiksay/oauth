//! `/api/v1/applications` — app registrations. Built-in apps
//! (`management-api`, `admin-portal`, `my-account`) can't be deleted; only a
//! GlobalAdmin may change them, and only their display name, token
//! lifetimes and MFA policy.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::{
    applications,
    enums::{AccessTokenFormat, ClientType, GroupsClaimFormat, IdTokenGroups, SigningAlg},
};
use sea_orm::{
    ActiveEnum, ActiveModelTrait, ActiveValue::Set, ColumnTrait, DbErr, EntityTrait, QueryFilter,
    TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    app_body::{AppBody, apply, parse},
    app_rules::{DEFAULT_REFRESH_TTL_PUBLIC, ensure_may_manage_credentials, find_app},
    extract::{Json, Path, Query},
    page::{self, Order, PageParams, Paged},
    search, ts, validate,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    cors, directory,
    error::{AppError, AppResult},
    oidc::scope,
    secret,
};

pub fn view(a: &applications::Model) -> Value {
    json!({
        "id": a.id,
        "client_id": a.client_id,
        "display_name": a.display_name,
        "client_type": a.client_type.to_value(),
        "builtin": a.builtin,
        "redirect_uris": a.redirect_uris,
        "post_logout_redirect_uris": a.post_logout_redirect_uris,
        "web_origins": a.web_origins,
        "effective_web_origins": cors::effective_origins(a),
        "identifier_uri": a.identifier_uri,
        "audience": scope::audience(a),
        "access_token_format": a.access_token_format.to_value(),
        "signing_alg": a.signing_alg.to_value(),
        "groups_claim_format": a.groups_claim_format.to_value(),
        "id_token_groups": a.id_token_groups.to_value(),
        "assignment_required": a.assignment_required,
        "access_token_ttl_secs": a.access_token_ttl_secs,
        "refresh_token_ttl_secs": a.refresh_token_ttl_secs,
        "device_code_enabled": a.device_code_enabled,
        "mfa_policy": a.mfa_policy.to_value(),
        "backchannel_logout_uri": a.backchannel_logout_uri,
        "backchannel_logout_session_required": a.backchannel_logout_session_required,
        "created_at": ts(&a.created_at),
        "updated_at": ts(&a.updated_at),
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
    caller.require(Area::Applications, Access::Read)?;
    let mut select =
        applications::Entity::find().filter(applications::Column::TenantId.eq(caller.tenant_id()));
    if let Some(cond) = search(
        q.search.as_deref(),
        &[
            applications::Column::DisplayName,
            applications::Column::ClientId,
        ],
    )? {
        select = select.filter(cond);
    }
    let page = page::fetch(
        &state.db,
        select,
        applications::Column::Id,
        q.page.parse()?,
        Order::Ascending,
        |a| a.id,
    )
    .await?;
    Ok(page.map(|a| view(&a)))
}

pub async fn get(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Applications, Access::Read)?;
    Ok(axum::Json(view(
        &find_app(&state.db, caller.tenant_id(), id).await?,
    )))
}

fn map_write_error(err: DbErr) -> AppError {
    if directory::violates_unique(&err, "applications_tenant_id_client_id_key") {
        AppError::Conflict("client_id is already taken in this tenant".into())
    } else if directory::violates_unique(&err, "applications_tenant_id_identifier_uri_key") {
        AppError::Conflict("identifier_uri is already used by another application".into())
    } else {
        err.into()
    }
}

pub async fn create(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<AppBody>,
) -> AppResult<Response> {
    caller.require(Area::Applications, Access::Write)?;
    let client_id = match &body.client_id {
        Some(id) => {
            validate::client_id(id)?;
            id.clone()
        }
        None => secret::random_uuid()?.to_string(),
    };
    let client_type: ClientType = match &body.client_type {
        Some(raw) => parse(raw, "client_type", "confidential, public")?,
        None => ClientType::Confidential,
    };
    if body.display_name.is_none() {
        return Err(AppError::BadRequest("display_name is required".into()));
    }
    let mut row = applications::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(caller.tenant_id()),
        client_id: Set(client_id.clone()),
        client_type: Set(client_type),
        builtin: Set(false),
        redirect_uris: Set(Vec::new()),
        post_logout_redirect_uris: Set(Vec::new()),
        web_origins: Set(Vec::new()),
        identifier_uri: Set(None),
        access_token_format: Set(AccessTokenFormat::Jwt),
        signing_alg: Set(SigningAlg::Rs256),
        groups_claim_format: Set(GroupsClaimFormat::Id),
        id_token_groups: Set(IdTokenGroups::None),
        ..Default::default()
    };
    if client_type == ClientType::Public {
        row.refresh_token_ttl_secs = Set(DEFAULT_REFRESH_TTL_PUBLIC);
    }
    let loopback = state.config.idp_allow_http_loopback;
    apply(&mut row, &body, &client_id, client_type, loopback)?;
    let txn = state.db.begin().await?;
    let app = applications::Entity::insert(row)
        .exec_with_returning(&txn)
        .await
        .map_err(map_write_error)?;
    caller
        .audit(
            &txn,
            EventType::ApplicationCreate,
            Some(Target::Application(app.id)),
            json!({ "client_id": app.client_id }),
        )
        .await?;
    txn.commit().await?;
    Ok((StatusCode::CREATED, axum::Json(view(&app))).into_response())
}

const BUILTIN_EDITABLE: [&str; 4] = [
    "display_name",
    "access_token_ttl_secs",
    "refresh_token_ttl_secs",
    "mfa_policy",
];

pub async fn update(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
    Json(body): Json<AppBody>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Applications, Access::Write)?;
    if body.client_id.is_some() || body.client_type.is_some() {
        return Err(AppError::BadRequest(
            "client_id and client_type can't be changed".into(),
        ));
    }
    let txn = state.db.begin().await?;
    let app = find_app(&txn, caller.tenant_id(), id).await?;
    let mut row: applications::ActiveModel = app.clone().into();
    let loopback = state.config.idp_allow_http_loopback;
    let fields = apply(&mut row, &body, &app.client_id, app.client_type, loopback)?;
    if fields.is_empty() {
        return Ok(axum::Json(view(&app)));
    }
    if app.builtin {
        caller.require_global_admin("change built-in applications")?;
        if fields.iter().any(|f| !BUILTIN_EDITABLE.contains(f)) {
            return Err(AppError::Forbidden(format!(
                "built-in applications only allow changing: {}",
                BUILTIN_EDITABLE.join(", ")
            )));
        }
    }
    // Each opens a way to obtain the app's tokens (or, for the back-channel
    // URI, its users' session ids), like a credential.
    if fields.iter().any(|f| {
        matches!(
            *f,
            "redirect_uris"
                | "post_logout_redirect_uris"
                | "web_origins"
                | "device_code_enabled"
                | "backchannel_logout_uri"
        )
    }) {
        ensure_may_manage_credentials(&txn, &caller, &app).await?;
    }
    row.updated_at = Set(chrono::Utc::now().fixed_offset());
    let updated = row.update(&txn).await.map_err(map_write_error)?;
    caller
        .audit(
            &txn,
            EventType::ApplicationUpdate,
            Some(Target::Application(id)),
            json!({ "client_id": updated.client_id, "fields": fields }),
        )
        .await?;
    txn.commit().await?;
    Ok(axum::Json(view(&updated)))
}

/// Deletes the registration; its secrets, scopes, roles, assignments,
/// grants and tokens cascade.
pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    caller.require(Area::Applications, Access::Write)?;
    let txn = state.db.begin().await?;
    let app = find_app(&txn, caller.tenant_id(), id).await?;
    if app.builtin {
        return Err(AppError::Forbidden(
            "built-in applications can't be deleted".into(),
        ));
    }
    applications::Entity::delete_by_id(id).exec(&txn).await?;
    caller
        .audit(
            &txn,
            EventType::ApplicationDelete,
            Some(Target::Application(id)),
            json!({ "client_id": app.client_id }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
