//! Token endpoint, `grant_type=urn:ietf:params:oauth:grant-type:device_code`
//! (RFC 8628 §3.4–3.5). The device polls with its device code; everything
//! happens on the request's row lock, so polls, the single redemption and
//! token issuance serialize per device code.

use std::{collections::HashMap, net::IpAddr};

use axum::http::{HeaderMap, header};
use chrono::Duration;
use entity::{applications, device_authorizations, enums::DeviceStatus};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde_json::json;
use uuid::Uuid;

use super::{
    error::{ErrorCode, OAuthError, OAuthResult},
    scope,
    token::{active_user, ensure_assigned, load_app},
};
use crate::{
    app::AppState,
    audit,
    authn::session::{self, NewSession},
    device_flow,
    tenancy::Tenant,
    tokens::{self, Delegated, Refresh, TokenSet},
};

pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

pub async fn grant(
    state: &AppState,
    tenant: &Tenant,
    ip: Option<IpAddr>,
    headers: &HeaderMap,
    client: &applications::Model,
    params: &HashMap<String, String>,
) -> OAuthResult<TokenSet> {
    if !client.device_code_enabled {
        return Err(OAuthError::new(
            ErrorCode::UnauthorizedClient,
            "the device code grant is not enabled for this client",
        ));
    }
    let device_code = params
        .get("device_code")
        .ok_or_else(|| OAuthError::invalid_request("device_code is required"))?;
    let txn = state.db.begin().await?;
    let row = device_flow::lock_by_device_code(&txn, tenant.id, device_code)
        .await?
        .filter(|row| row.application_id == client.id)
        .ok_or_else(|| OAuthError::invalid_grant("unknown device_code"))?;
    if row.consumed_at.is_some() {
        return Err(OAuthError::invalid_grant("device_code already used"));
    }
    let now = chrono::Utc::now().fixed_offset();
    if row.expires_at <= now {
        return Err(OAuthError::new(
            ErrorCode::ExpiredToken,
            "the device code has expired",
        ));
    }
    match row.status {
        DeviceStatus::Pending => {
            let slow_down = device_flow::record_poll(&txn, &row, now).await?;
            txn.commit().await?;
            Err(if slow_down {
                OAuthError::new(ErrorCode::SlowDown, "polling too fast")
            } else {
                OAuthError::new(
                    ErrorCode::AuthorizationPending,
                    "the user has not finished yet",
                )
            })
        }
        DeviceStatus::Denied => Err(OAuthError::new(
            ErrorCode::AccessDenied,
            "the user denied the request",
        )),
        DeviceStatus::Approved => {
            let user_agent = headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok());
            let set = redeem(state, &txn, tenant, ip, user_agent, client, &row).await?;
            txn.commit().await?;
            Ok(set)
        }
    }
}

/// Consumes the approved request and issues its tokens on the caller's
/// transaction. The device gets a session of its own (no cookie; its id is
/// the tokens' `sid`), carrying the approving sign-in's `amr` / `auth_time`
/// and lasting at least as long as its refresh tokens.
async fn redeem(
    state: &AppState,
    txn: &impl ConnectionTrait,
    tenant: &Tenant,
    ip: Option<IpAddr>,
    user_agent: Option<&str>,
    client: &applications::Model,
    row: &device_authorizations::Model,
) -> OAuthResult<TokenSet> {
    let (Some(user_id), Some(auth_time)) = (row.user_id, row.auth_time) else {
        return Err(anyhow::anyhow!("approved device authorization without its user").into());
    };
    let user = active_user(txn, tenant.id, user_id).await?;
    let resource = load_app(txn, row.resource_application_id).await?;
    // The assignment may have gone since the user approved.
    ensure_assigned(txn, tenant, &user, client, resource.as_ref()).await?;
    let (oidc, resource_scopes) = scope::split_stored(&row.scopes);
    device_flow::consume(txn, row.id).await?;
    let now = chrono::Utc::now().fixed_offset();
    let refresh = oidc.iter().any(|s| s == "offline_access").then(|| Refresh {
        family_id: Uuid::now_v7(),
        expires_at: now + Duration::seconds(i64::from(client.refresh_token_ttl_secs)),
        scopes: row.scopes.clone(),
        resource_app_id: row.resource_application_id,
    });
    // The session is how the user finds and signs out the device (My
    // Account), so it lives as long as the refresh family (whose expiry
    // rotation keeps); refresh never checks the session itself.
    let (session, _unused_cookie) = session::create(
        txn,
        &state.config,
        NewSession {
            tenant_id: tenant.id,
            user_id,
            amr: &row.amr,
            auth_time,
            ip,
            user_agent,
            min_expires_at: refresh.as_ref().map(|r| r.expires_at),
        },
    )
    .await?;
    let issuer = state.config.issuer(&tenant.slug);
    let set = tokens::issue_delegated(
        txn,
        &state.config.master_key,
        Delegated {
            tenant,
            issuer: &issuer,
            client,
            user: &user,
            session_id: session.id,
            amr: &row.amr,
            auth_time,
            nonce: None,
            oidc_scopes: &oidc,
            resource: resource.as_ref(),
            resource_scopes: &resource_scopes,
            authorization_code_id: None,
            refresh,
        },
    )
    .await?;
    audit::record(
        txn,
        audit::Event {
            tenant_id: tenant.id,
            actor: audit::Actor::Application(client.id),
            event_type: audit::EventType::DeviceCodeRedeem,
            target: Some(audit::Target::User(user_id)),
            outcome: entity::enums::Outcome::Success,
            ip,
            details: json!({
                "device_authorization_id": row.id,
                "session_id": session.id,
            }),
        },
    )
    .await?;
    Ok(set)
}
