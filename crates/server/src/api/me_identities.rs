//! `me/identities…` — the signed-in user's linked upstream identities:
//! list, link (re-authenticated, then an upstream round trip that ends in
//! `GET /federation/callback`), unlink (re-authenticated; never the last
//! sign-in method).

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use entity::enums::Outcome as AuditOutcome;
use sea_orm::TransactionTrait;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    extract::{Json, Path},
    guard::lock_user,
    me::me,
    reauth::ReauthBody,
    user_identities,
};
use crate::{
    app::AppState,
    audit,
    authn::cookie::{self, Kind},
    error::{AppError, AppResult},
    federation::{flow, identities, idps, state::Owner},
    secret,
};

pub async fn list(State(state): State<AppState>, caller: Caller) -> AppResult<axum::Json<Value>> {
    let user = me(&state, &caller).await?;
    let linked = identities::list(&state.db, user.tenant_id, user.id).await?;
    let available: Vec<Value> = idps::enabled(&state.db, user.tenant_id)
        .await?
        .iter()
        .filter(|idp| !linked.iter().any(|(i, _)| i.idp_id == idp.id))
        .map(|idp| json!({ "id": idp.id, "name": idp.name }))
        .collect();
    let items: Vec<Value> = linked
        .iter()
        .map(|(identity, name)| user_identities::view(identity, name, false))
        .collect();
    Ok(axum::Json(
        json!({ "items": items, "available": available }),
    ))
}

/// `{ redirect }` to the provider. The round trip is bound to this browser
/// through the tx-binding cookie (set here when missing), so a link started
/// by someone else can't be completed in the victim's browser.
pub async fn link(
    State(state): State<AppState>,
    caller: Caller,
    headers: HeaderMap,
    Path(idp_id): Path<Uuid>,
    Json(body): Json<ReauthBody>,
) -> AppResult<Response> {
    let user = me(&state, &caller).await?;
    let idp = idps::find_enabled(&state.db, user.tenant_id, idp_id)
        .await?
        .ok_or(AppError::NotFound)?;
    body.verify(&state, &caller, &user).await?;
    let linked = identities::list(&state.db, user.tenant_id, user.id).await?;
    if linked.iter().any(|(i, _)| i.idp_id == idp.id) {
        return Err(AppError::Conflict(
            "an account of this identity provider is already linked".into(),
        ));
    }
    let binding =
        match cookie::read(&headers, &state.config, Kind::TxBinding).find(|v| v.len() == 43) {
            Some(existing) => existing.to_owned(),
            None => secret::random_token()?,
        };
    let session_id = caller
        .session_id
        .ok_or_else(|| AppError::Forbidden("linking needs a signed-in session".into()))?;
    let owner = Owner::Link {
        user_id: user.id,
        session_id,
    };
    let hash = secret::hash(&binding);
    match flow::begin(
        &state,
        &caller.tenant.slug,
        &idp,
        owner,
        &hash,
        flow::Reauth::default(),
    )
    .await?
    {
        Ok(url) => {
            let set = cookie::set(&state.config, Kind::TxBinding, &binding)?;
            let mut response = axum::Json(json!({ "redirect": url })).into_response();
            response.headers_mut().append(header::SET_COOKIE, set);
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                "no-store".parse().map_err(anyhow::Error::from)?,
            );
            Ok(response)
        }
        Err(failure) => {
            audit::record(
                &state.db,
                audit::Event {
                    tenant_id: user.tenant_id,
                    actor: audit::Actor::User(Some(user.id)),
                    event_type: audit::EventType::UserIdentityLink,
                    target: Some(audit::Target::User(user.id)),
                    outcome: AuditOutcome::Failure,
                    ip: caller.ip,
                    details: flow::failure_details(failure.0, idp.id),
                },
            )
            .await?;
            Err(AppError::Unavailable)
        }
    }
}

pub async fn unlink(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<Uuid>,
    Json(body): Json<ReauthBody>,
) -> AppResult<StatusCode> {
    let user = me(&state, &caller).await?;
    identities::find_for_user(&state.db, user.tenant_id, user.id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    body.verify(&state, &caller, &user).await?;
    let txn = state.db.begin().await?;
    // Locked: two concurrent unlinks can't both pass the last-method check.
    let user = lock_user(&txn, user.tenant_id, user.id).await?;
    user_identities::unlink(&txn, &caller, &user, id, "me").await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
