//! `/api/v1/tenants[/{tenant}]` — Global Admins of the system tenant only
//! (delegated tokens of the `system` tenant; app-only tokens never manage
//! tenants) — and `/api/v1/tenants/{t}/settings` for a tenant's own admins.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::{enums::DirectoryRole, tenants};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectionTrait, EntityTrait, QueryFilter, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    Caller,
    auth::SystemAdmin,
    extract::{Json, Path, Query},
    page::{self, Order, PageParams, Paged},
    search, ts,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    directory::{self, NewTenant, NewUser, display_name, normalize_email, password, slug},
    error::{AppError, AppResult},
};

/// Bounds for `audit_retention_days` (the DB only requires > 0). The floor
/// keeps a tenant admin from erasing recent history by shrinking retention.
const RETENTION_DAYS: std::ops::RangeInclusive<i32> = 30..=3650;

pub fn view(t: &tenants::Model) -> Value {
    json!({
        "id": t.id,
        "slug": t.slug,
        "display_name": t.display_name,
        "is_system": t.is_system,
        "disabled": t.disabled,
        "audit_retention_days": t.audit_retention_days,
        "created_at": ts(&t.created_at),
        "updated_at": ts(&t.updated_at),
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
    _admin: SystemAdmin,
    Query(q): Query<ListQuery>,
) -> AppResult<Paged<Value>> {
    let mut select = tenants::Entity::find();
    if let Some(cond) = search(
        q.search.as_deref(),
        &[tenants::Column::Slug, tenants::Column::DisplayName],
    )? {
        select = select.filter(cond);
    }
    let page = page::fetch(
        &state.db,
        select,
        tenants::Column::Id,
        q.page.parse()?,
        Order::Ascending,
        |t| t.id,
    )
    .await?;
    Ok(page.map(|t| view(&t)))
}

async fn by_slug(conn: &impl ConnectionTrait, slug: &str) -> AppResult<tenants::Model> {
    if slug::validate_format(slug).is_err() {
        return Err(AppError::NotFound);
    }
    directory::find_tenant_by_slug(conn, slug)
        .await?
        .ok_or(AppError::NotFound)
}

pub async fn get(
    State(state): State<AppState>,
    _admin: SystemAdmin,
    Path(slug): Path<String>,
) -> AppResult<axum::Json<Value>> {
    Ok(axum::Json(view(&by_slug(&state.db, &slug).await?)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTenant {
    slug: String,
    display_name: String,
    admin_email: String,
    admin_display_name: Option<String>,
}

/// Creates the tenant (keys, built-in apps) and its first Global Admin with
/// a one-time password — all in one transaction.
pub async fn create(
    State(state): State<AppState>,
    SystemAdmin(caller): SystemAdmin,
    Json(body): Json<CreateTenant>,
) -> AppResult<Response> {
    // Validate before the slow key generation.
    slug::validate(&body.slug)?;
    display_name(&body.display_name, "tenant")?;
    let email = normalize_email(&body.admin_email)?;
    let admin_name = body
        .admin_display_name
        .as_deref()
        .unwrap_or("Administrator");
    display_name(admin_name, "user")?;

    let keys = directory::generate_tenant_keys().await?;
    let one_time = Zeroizing::new(password::generate_one_time()?);
    let txn = state.db.begin().await?;
    let new = NewTenant {
        slug: &body.slug,
        display_name: &body.display_name,
    };
    let tenant = directory::insert_tenant(&txn, &state.config, new, &keys).await?;
    let admin = directory::create_user(
        &txn,
        tenant.id,
        NewUser {
            email: &email,
            display_name: admin_name,
            password: Some(&one_time),
            must_change_password: true,
        },
    )
    .await?;
    directory::assign_directory_role(&txn, tenant.id, admin.id, DirectoryRole::GlobalAdmin).await?;
    let details = json!({ "slug": tenant.slug, "admin_user_id": admin.id });
    caller
        .audit(
            &txn,
            EventType::TenantCreate,
            Some(Target::Tenant(tenant.id)),
            details,
        )
        .await?;
    txn.commit().await?;
    let body = json!({
        "tenant": view(&tenant),
        "admin": { "id": admin.id, "email": admin.email },
        "one_time_password": one_time.as_str(),
    });
    Ok((StatusCode::CREATED, axum::Json(body)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTenant {
    display_name: Option<String>,
    disabled: Option<bool>,
    audit_retention_days: Option<i32>,
}

/// Validates and stores the changes on `txn` (loading the tenant there),
/// auditing them as `caller`.
async fn save(
    txn: &impl ConnectionTrait,
    caller: &Caller,
    slug: &str,
    body: &UpdateTenant,
) -> AppResult<tenants::Model> {
    let tenant = by_slug(txn, slug).await?;
    if tenant.is_system && body.disabled == Some(true) {
        return Err(AppError::Forbidden(
            "the system tenant cannot be disabled".into(),
        ));
    }
    let mut row: tenants::ActiveModel = tenant.clone().into();
    let mut fields = Vec::new();
    if let Some(name) = &body.display_name {
        row.display_name = Set(display_name(name, "tenant")?);
        fields.push("display_name");
    }
    if let Some(disabled) = body.disabled {
        row.disabled = Set(disabled);
        fields.push("disabled");
    }
    if let Some(days) = body.audit_retention_days {
        if !RETENTION_DAYS.contains(&days) {
            return Err(AppError::BadRequest(format!(
                "audit_retention_days must be {}-{}",
                RETENTION_DAYS.start(),
                RETENTION_DAYS.end()
            )));
        }
        row.audit_retention_days = Set(days);
        fields.push("audit_retention_days");
    }
    if fields.is_empty() {
        return Ok(tenant);
    }
    row.updated_at = Set(chrono::Utc::now().fixed_offset());
    let updated = row.update(txn).await?;
    let details = json!({ "slug": updated.slug, "fields": fields, "disabled": updated.disabled });
    let target = Some(Target::Tenant(updated.id));
    caller
        .audit(txn, EventType::TenantUpdate, target, details.clone())
        .await?;
    // A system admin changing another tenant: that tenant's admins see it in
    // their own log too.
    if updated.id != caller.tenant_id() {
        caller
            .audit_in(txn, updated.id, EventType::TenantUpdate, target, details)
            .await?;
    }
    Ok(updated)
}

/// Rename, disable / enable, retention. Disabling makes the tenant 404
/// everywhere (sign-in, tokens, management API).
pub async fn update(
    State(state): State<AppState>,
    SystemAdmin(caller): SystemAdmin,
    Path(slug): Path<String>,
    Json(body): Json<UpdateTenant>,
) -> AppResult<axum::Json<Value>> {
    let txn = state.db.begin().await?;
    let updated = save(&txn, &caller, &slug, &body).await?;
    txn.commit().await?;
    Ok(axum::Json(view(&updated)))
}

/// `GET …/tenants/{t}/settings`: the caller's own tenant (any directory
/// role or app with read access).
pub async fn get_settings(caller: Caller) -> AppResult<axum::Json<Value>> {
    caller.require(Area::Directory, Access::Read)?;
    Ok(axum::Json(view(&caller.tenant)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    display_name: Option<String>,
    audit_retention_days: Option<i32>,
}

/// `PATCH …/tenants/{t}/settings`: a tenant's own Global Admin renames it
/// or sets its audit retention (creating, disabling and enabling tenants
/// stay with the system tenant's admins).
pub async fn update_settings(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<Settings>,
) -> AppResult<axum::Json<Value>> {
    caller.require_global_admin("change tenant settings")?;
    let body = UpdateTenant {
        display_name: body.display_name,
        disabled: None,
        audit_retention_days: body.audit_retention_days,
    };
    let txn = state.db.begin().await?;
    let updated = save(&txn, &caller, &caller.tenant.slug, &body).await?;
    txn.commit().await?;
    Ok(axum::Json(view(&updated)))
}
