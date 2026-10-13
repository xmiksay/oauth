//! `/api/v1/tenants/{t}/applications` — app registrations. Built-in apps
//! (`management-api`, `admin-portal`, `my-account`) can't be deleted; only a
//! GlobalAdmin may change them, and only their display name and token
//! lifetimes.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::{
    applications,
    enums::{AccessTokenFormat, ClientType, SigningAlg},
};
use sea_orm::{
    ActiveEnum, ActiveModelTrait, ActiveValue::Set, ColumnTrait, DbErr, EntityTrait, QueryFilter,
    TransactionTrait,
};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    app_rules::{
        ACCESS_TTL, DEFAULT_REFRESH_TTL_PUBLIC, ensure_may_manage_credentials, find_app,
        refresh_ttl,
    },
    extract::{Json, Path, Query},
    page::{self, Order, PageParams, Paged},
    search, ts, validate,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    directory::{self, display_name},
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
        "identifier_uri": a.identifier_uri,
        "audience": scope::audience(a),
        "access_token_format": a.access_token_format.to_value(),
        "signing_alg": a.signing_alg.to_value(),
        "access_token_ttl_secs": a.access_token_ttl_secs,
        "refresh_token_ttl_secs": a.refresh_token_ttl_secs,
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
    Path((_, id)): Path<(String, Uuid)>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Applications, Access::Read)?;
    Ok(axum::Json(view(
        &find_app(&state.db, caller.tenant_id(), id).await?,
    )))
}

/// `Some(None)` = explicit `null` (clear), `None` = absent (keep).
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

/// Create and update body. `client_id` / `client_type` are create-only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppBody {
    client_id: Option<String>,
    client_type: Option<String>,
    display_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(default, deserialize_with = "nullable")]
    identifier_uri: Option<Option<String>>,
    access_token_format: Option<String>,
    signing_alg: Option<String>,
    access_token_ttl_secs: Option<i32>,
    refresh_token_ttl_secs: Option<i32>,
}

fn parse<E: ActiveEnum<Value = String>>(raw: &str, field: &str, allowed: &str) -> AppResult<E> {
    E::try_from_value(&raw.to_owned())
        .map_err(|_| AppError::BadRequest(format!("{field} must be one of: {allowed}")))
}

/// Validates and applies the settable fields; returns the changed names.
fn apply(
    row: &mut applications::ActiveModel,
    body: &AppBody,
    client_id: &str,
    client_type: ClientType,
) -> AppResult<Vec<&'static str>> {
    let mut fields = Vec::new();
    if let Some(name) = &body.display_name {
        row.display_name = Set(display_name(name, "application")?);
        fields.push("display_name");
    }
    if let Some(uris) = &body.redirect_uris {
        validate::redirect_uris(uris, "redirect_uris")?;
        row.redirect_uris = Set(uris.clone());
        fields.push("redirect_uris");
    }
    if let Some(uris) = &body.post_logout_redirect_uris {
        validate::redirect_uris(uris, "post_logout_redirect_uris")?;
        row.post_logout_redirect_uris = Set(uris.clone());
        fields.push("post_logout_redirect_uris");
    }
    if let Some(uri) = &body.identifier_uri {
        if let Some(uri) = uri {
            validate::identifier_uri(uri, client_id)?;
        }
        row.identifier_uri = Set(uri.clone());
        fields.push("identifier_uri");
    }
    if let Some(raw) = &body.access_token_format {
        let format: AccessTokenFormat = parse(raw, "access_token_format", "jwt, opaque")?;
        row.access_token_format = Set(format);
        fields.push("access_token_format");
    }
    if let Some(raw) = &body.signing_alg {
        let alg: SigningAlg = parse(raw, "signing_alg", "RS256, ES256")?;
        row.signing_alg = Set(alg);
        fields.push("signing_alg");
    }
    if let Some(ttl) = body.access_token_ttl_secs {
        if !ACCESS_TTL.contains(&ttl) {
            return Err(AppError::BadRequest(
                "access_token_ttl_secs must be 300-86400".into(),
            ));
        }
        row.access_token_ttl_secs = Set(ttl);
        fields.push("access_token_ttl_secs");
    }
    if let Some(ttl) = body.refresh_token_ttl_secs {
        refresh_ttl(client_type, ttl)?;
        row.refresh_token_ttl_secs = Set(ttl);
        fields.push("refresh_token_ttl_secs");
    }
    Ok(fields)
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
        identifier_uri: Set(None),
        access_token_format: Set(AccessTokenFormat::Jwt),
        signing_alg: Set(SigningAlg::Rs256),
        ..Default::default()
    };
    if client_type == ClientType::Public {
        row.refresh_token_ttl_secs = Set(DEFAULT_REFRESH_TTL_PUBLIC);
    }
    apply(&mut row, &body, &client_id, client_type)?;
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

const BUILTIN_EDITABLE: [&str; 3] = [
    "display_name",
    "access_token_ttl_secs",
    "refresh_token_ttl_secs",
];

pub async fn update(
    State(state): State<AppState>,
    caller: Caller,
    Path((_, id)): Path<(String, Uuid)>,
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
    let fields = apply(&mut row, &body, &app.client_id, app.client_type)?;
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
    if fields
        .iter()
        .any(|f| matches!(*f, "redirect_uris" | "post_logout_redirect_uris"))
    {
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
    Path((_, id)): Path<(String, Uuid)>,
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
