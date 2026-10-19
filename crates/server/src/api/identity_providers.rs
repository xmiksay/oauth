//! `/api/v1/identity-providers` — the tenant's upstream OpenID providers.
//! Any directory role reads, only a GlobalAdmin writes (`Area::IdentityProviders`).
//! The client secret is write-only: sealed at rest, never returned.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entity::{
    enums::{IdpClientAuth, IdpKind, IdpPolicy},
    identity_providers,
};
use sea_orm::{
    ActiveEnum, ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait,
    QueryFilter, QuerySelect, TransactionTrait,
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    extract::{Json, Path, Query},
    guard::conflict_on_unique,
    idp_body::{IdpBody, apply, ensure_domains_free, seal},
    page::{self, Order, PageParams, Paged},
    ts,
};
use crate::{
    app::AppState,
    audit::{EventType, Target},
    authz::{Access, Area},
    error::{AppError, AppResult},
    federation::{identities, idps, urls},
};

fn view(state: &AppState, caller: &Caller, idp: &identity_providers::Model) -> Value {
    json!({
        "id": idp.id,
        "name": idp.name,
        "kind": idp.kind.to_value(),
        "enabled": idp.enabled,
        "visible": idp.visible,
        "issuer": idp.issuer,
        "discovery_url": idp.discovery_url,
        "client_id": idp.client_id,
        "has_secret": idp.client_secret_sealed.is_some(),
        "client_auth": idp.client_auth.to_value(),
        "scopes": idp.scopes,
        "policy": idp.policy.to_value(),
        "trust_upstream_mfa": idp.trust_upstream_mfa,
        "mfa_acr": idp.mfa_acr,
        "email_domains": idp.email_domains,
        "redirect_uri": urls::callback_url(&state.config, &caller.tenant.slug),
        "created_at": ts(&idp.created_at),
        "updated_at": ts(&idp.updated_at),
    })
}

/// [`view`] plus `users_only_via` (lockout warning) and `linked_users`.
async fn detailed(
    state: &AppState,
    caller: &Caller,
    conn: &impl ConnectionTrait,
    idp: &identity_providers::Model,
) -> AppResult<Value> {
    let mut out = view(state, caller, idp);
    let only_via = identities::users_only_via(conn, idp.tenant_id, idp.id).await?;
    let linked = identities::linked_users(conn, idp.tenant_id, idp.id).await?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("users_only_via".into(), json!(only_via));
        obj.insert("linked_users".into(), json!(linked));
    }
    Ok(out)
}

async fn find(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    id: Uuid,
) -> AppResult<identity_providers::Model> {
    idps::find(conn, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound)
}

pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    Query(q): Query<PageParams>,
) -> AppResult<Paged<Value>> {
    caller.require(Area::IdentityProviders, Access::Read)?;
    let select = identity_providers::Entity::find()
        .filter(identity_providers::Column::TenantId.eq(caller.tenant_id()));
    let page = page::fetch(
        &state.db,
        select,
        identity_providers::Column::Id,
        q.parse()?,
        Order::Ascending,
        |i| i.id,
    )
    .await?;
    Ok(page.map(|idp| view(&state, &caller, &idp)))
}

pub async fn get(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::IdentityProviders, Access::Read)?;
    let idp = find(&state.db, caller.tenant_id(), id).await?;
    Ok(axum::Json(
        detailed(&state, &caller, &state.db, &idp).await?,
    ))
}

pub async fn create(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<IdpBody>,
) -> AppResult<Response> {
    caller.require(Area::IdentityProviders, Access::Write)?;
    let (Some(_), Some(_), Some(_)) = (&body.name, &body.issuer, &body.client_id) else {
        return Err(AppError::BadRequest(
            "name, issuer and client_id are required".into(),
        ));
    };
    let tenant_id = caller.tenant_id();
    let id = Uuid::now_v7();
    let now = chrono::Utc::now().fixed_offset();
    let mut row = identity_providers::ActiveModel {
        id: Set(id),
        tenant_id: Set(tenant_id),
        kind: Set(IdpKind::Oidc),
        enabled: Set(true),
        visible: Set(true),
        discovery_url: Set(None),
        client_secret_sealed: Set(None),
        client_auth: Set(IdpClientAuth::Post),
        scopes: Set(["openid", "email", "profile"].map(str::to_owned).to_vec()),
        policy: Set(IdpPolicy::LinkOnly),
        trust_upstream_mfa: Set(false),
        mfa_acr: Set(None),
        email_domains: Set(Vec::new()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    let mut secret = None;
    apply(&state, &mut row, &body, &mut secret)?;
    seal(&state, &mut row, tenant_id, id, secret)?;
    let txn = state.db.begin().await?;
    if let Set(domains) = &row.email_domains {
        ensure_domains_free(&txn, tenant_id, id, domains).await?;
    }
    let idp = identity_providers::Entity::insert(row)
        .exec_with_returning(&txn)
        .await
        .map_err(|err| conflict_on_unique(err, "an identity provider with this name exists"))?;
    caller
        .audit(
            &txn,
            EventType::IdentityProviderCreate,
            Some(Target::IdentityProvider(idp.id)),
            json!({ "name": idp.name, "issuer": idp.issuer, "policy": idp.policy.to_value() }),
        )
        .await?;
    txn.commit().await?;
    let out = detailed(&state, &caller, &state.db, &idp).await?;
    Ok((StatusCode::CREATED, axum::Json(out)).into_response())
}

pub async fn update(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
    Json(body): Json<IdpBody>,
) -> AppResult<axum::Json<Value>> {
    caller.require(Area::IdentityProviders, Access::Write)?;
    let tenant_id = caller.tenant_id();
    let txn = state.db.begin().await?;
    // FOR UPDATE: sign-ins and links hold it FOR SHARE while they write, so
    // a repoint waits for them, and they see the new generation after it.
    let idp = identity_providers::Entity::find_by_id(id)
        .filter(identity_providers::Column::TenantId.eq(tenant_id))
        .lock_exclusive()
        .one(&txn)
        .await?
        .ok_or(AppError::NotFound)?;
    let mut row: identity_providers::ActiveModel = idp.clone().into();
    let mut secret = None;
    let mut fields = apply(&state, &mut row, &body, &mut secret)?;
    let repointed = ["issuer", "client_id", "discovery_url"]
        .iter()
        .any(|f| fields.contains(f));
    // A secret only ever goes to the provider it was entered for: pointing
    // the IdP elsewhere drops it unless a new one comes with the change.
    let moved = fields.contains(&"issuer") || fields.contains(&"discovery_url");
    if moved && secret.is_none() && idp.client_secret_sealed.is_some() {
        row.client_secret_sealed = Set(None);
        if !fields.contains(&"client_secret") {
            fields.push("client_secret");
        }
    }
    if repointed {
        row.generation = Set(idp.generation.saturating_add(1));
    }
    if fields.is_empty() {
        return Ok(axum::Json(detailed(&state, &caller, &txn, &idp).await?));
    }
    seal(&state, &mut row, tenant_id, id, secret)?;
    if fields.contains(&"email_domains") {
        let domains = row.email_domains.try_as_ref().cloned().unwrap_or_default();
        ensure_domains_free(&txn, tenant_id, id, &domains).await?;
    }
    row.updated_at = Set(chrono::Utc::now().fixed_offset());
    let updated = row
        .update(&txn)
        .await
        .map_err(|err| conflict_on_unique(err, "an identity provider with this name exists"))?;
    // Another issuer, client or discovery source means other subjects:
    // keeping the links would hand the old users' accounts to whoever the
    // new provider calls by those subjects.
    let removed = if repointed {
        identities::unlink_all(&txn, tenant_id, id).await?
    } else {
        0
    };
    caller
        .audit(
            &txn,
            EventType::IdentityProviderUpdate,
            Some(Target::IdentityProvider(id)),
            json!({ "fields": fields, "identities_removed": removed }),
        )
        .await?;
    let out = detailed(&state, &caller, &txn, &updated).await?;
    txn.commit().await?;
    if let Some(upstream) = &state.upstream {
        upstream.forget(id);
    }
    Ok(axum::Json(out))
}

/// Allowed even when some users can sign in only through it (the UI warns
/// with `users_only_via`); their identities go with it.
pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    caller.require(Area::IdentityProviders, Access::Write)?;
    let txn = state.db.begin().await?;
    let idp = find(&txn, caller.tenant_id(), id).await?;
    let only_via = identities::users_only_via(&txn, idp.tenant_id, id).await?;
    identity_providers::Entity::delete_by_id(id)
        .exec(&txn)
        .await?;
    caller
        .audit(
            &txn,
            EventType::IdentityProviderDelete,
            Some(Target::IdentityProvider(id)),
            json!({ "name": idp.name, "users_only_via": only_via }),
        )
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
