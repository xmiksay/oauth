//! `GET /api/authn/tx/{id}`: what the login SPA needs to render the
//! current step of a transaction.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
};
use entity::{applications, enums::LoginStage, identity_providers};
use sea_orm::EntityTrait;
use serde_json::{Value, json};

use super::{
    AuthnError, AuthnResult, Outcome, complete,
    ctx::Ctx,
    ip::ClientIp,
    tx::{LoadedTx, load, unpark, user_of},
};
use crate::{app::AppState, consent::Decision, federation, tenancy::Tenant};

/// What the login SPA needs to render the current step.
pub async fn view(state: &AppState, tenant: &Tenant, tx: &LoadedTx) -> AuthnResult<Value> {
    let conn = &state.db;
    let client = applications::Entity::find_by_id(tx.row.application_id)
        .one(conn)
        .await?
        .ok_or(AuthnError::NotFound)?;
    let user = match tx.row.user_id {
        Some(_) => Some(user_of(conn, tx).await?),
        None => None,
    };
    let consent = match (&user, tx.row.stage) {
        (Some(user), LoginStage::Consent) => {
            let force = complete::force_consent(&tx.req);
            let resource = complete::pending_resource(conn, &client, tx.req.resource_id).await?;
            let eval = complete::evaluate_consent(
                conn,
                &client,
                &tx.req,
                resource.as_ref(),
                user.id,
                force,
            )
            .await?;
            let pending = match &eval.decision {
                Decision::NeedsUser(values) => values.clone(),
                Decision::Granted | Decision::NeedsAdmin(_) => Vec::new(),
            };
            // A device request lists everything the device will get.
            let device = tx.req.device.is_some();
            let scopes: Vec<Value> = eval
                .scopes
                .iter()
                .filter(|s| device || pending.contains(&s.value))
                .map(|s| json!({ "value": s.value, "description": s.description }))
                .collect();
            resource.map(|r| {
                json!({
                    "resource": {
                        "display_name": r.display_name,
                        "audience": crate::oidc::scope::audience(&r),
                    },
                    "scopes": scopes,
                })
            })
        }
        _ => None,
    };
    let idps = federation::idps::enabled(conn, tenant.id).await?;
    let mut stage = tx.row.stage;
    let mut notice = None;
    let mut link = None;
    let brief = |idp: &identity_providers::Model| json!({ "id": idp.id, "name": idp.name });
    if let (Some(raw), LoginStage::Link) = (&tx.row.pending_identity, stage) {
        let pending = super::federation_pending::decode(raw)?;
        match super::federation_pending::usable_idp(conn, tenant.id, &pending).await? {
            Some(idp) => {
                link = Some(json!({
                    "idp": brief(&idp),
                    "email": pending.email,
                    "name": pending.name,
                }));
            }
            // The provider went away while the identity was parked.
            None => {
                unpark(conn, tx.row.id).await?;
                stage = LoginStage::Password;
                notice = Some("link_unavailable");
            }
        }
    }
    let buttons: Vec<Value> = idps
        .iter()
        .filter(|idp| stage == LoginStage::Password && idp.visible)
        .map(brief)
        .collect();
    let hint = federation::idps::hinted(&idps, &tx.req).filter(|_| stage == LoginStage::Password);
    Ok(json!({
        "tx": tx.row.id,
        "step": stage.as_str(),
        "tenant": { "slug": tenant.slug, "display_name": tenant.display_name },
        "client": { "client_id": client.client_id, "display_name": client.display_name },
        "user": user.map(|u| json!({ "email": u.email, "display_name": u.display_name })),
        "consent": consent,
        "factors": super::passkey::factors(state, tx).await?,
        "enrolled": stage == LoginStage::MfaEnroll && super::mfa_policy::is_mfa(&tx.row.amr),
        "idps": buttons,
        "idp_hint": hint.map(brief),
        "link": link,
        "notice": notice,
        "device": tx.req.device.is_some(),
        "oidc_scopes": tx.req.oidc_scopes,
        "releases_groups": client.id_token_groups != entity::enums::IdTokenGroups::None,
        "features": {
            "password_reset": state.config.email_enabled(),
            "federation": !idps.is_empty(),
        },
    }))
}

pub async fn get(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let tx = load(&ctx, &tx_id).await?;
    Ok(Outcome::Step(view(&state, &tenant, &tx).await?))
}
