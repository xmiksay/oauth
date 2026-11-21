//! Browser side of the device authorization grant (RFC 8628). The SPA's
//! `/device` page submits the user code to `POST /api/authn/device`, which
//! starts an ordinary login transaction for that request (at the consent
//! step when this browser is signed in already). Its `AuthRequest.device`
//! makes completion approve the device request instead of issuing a code,
//! and errors land on `/device?…` instead of a client redirect URI.

use axum::{extract::State, http::HeaderMap};
use entity::{
    applications, device_authorizations,
    enums::{LoginStage, Outcome as AuditOutcome},
    sessions,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, TransactionTrait};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    AuthnError, AuthnResult, JsonBody, Outcome,
    complete::evaluate_consent,
    cookie::{self, Kind},
    ctx::Ctx,
    ip::ClientIp,
    rate_limit, session, tx,
};
use crate::{
    app::AppState,
    audit,
    consent::Decision as ConsentDecision,
    device_flow::{self, Decision, user_code},
    oidc::{error::ErrorCode, params::AuthRequest, scope},
    tenancy::Tenant,
};

#[derive(Deserialize)]
pub struct EnterBody {
    user_code: String,
}

pub async fn enter(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    JsonBody(body): JsonBody<EnterBody>,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let conn = &state.db;
    let now = chrono::Utc::now();
    // Counted before the lookup, so parallel guesses can't slip past it.
    let key = format!("usercode:{}", rate_limit::ip_key(ctx.ip));
    let limit = rate_limit::USER_CODE_PER_IP;
    if let Err(retry_after) = rate_limit::hit(conn, tenant.id, &key, limit, now).await? {
        return Err(AuthnError::RateLimited { retry_after });
    }
    let (key, misses) = (rate_limit::USER_CODE_MISS_KEY, rate_limit::USER_CODE_MISSES);
    if let Err(retry_after) = rate_limit::check(conn, tenant.id, key, misses, now).await? {
        return Err(AuthnError::RateLimited { retry_after });
    }
    // Unknown, expired, decided or of a client that opted out: all the same.
    let code = user_code::normalize(&body.user_code).ok_or(AuthnError::InvalidCode)?;
    let Some((row, client)) = find(conn, tenant.id, &code).await? else {
        // Only misses fill it, so users entering real codes don't.
        let _ = rate_limit::hit(conn, tenant.id, key, misses, now).await?;
        return Err(AuthnError::InvalidCode);
    };
    let (oidc, resource_scopes) = scope::split_stored(&row.scopes);
    let req = AuthRequest {
        client_id: client.client_id.clone(),
        redirect_uri: String::new(),
        state: None,
        nonce: None,
        code_challenge: String::new(),
        oidc_scopes: oidc,
        resource_id: row.resource_application_id,
        resource_scopes,
        prompt: None,
        max_age: None,
        domain_hint: None,
        idp: None,
        device: Some(row.id),
    };
    // Signed in already: straight to the confirmation, which a device
    // request always gets (a phished code must not approve silently) —
    // unless no user can consent to it, which is settled right here, as
    // `oidc::authorize` does, instead of after a pointless Allow.
    let current = session::current(conn, &state.config, &tenant, &headers).await?;
    let (stage, session) = match &current {
        Some((session, user)) => {
            let eval = evaluate_consent(conn, &client, &req, user.id, false).await?;
            if let ConsentDecision::NeedsAdmin(_) = eval.decision {
                let reason = "admin_consent_required";
                // Decision and audit event commit together.
                let txn = conn.begin().await?;
                deny(&txn, &ctx, row.id, client.id, user.id, reason).await?;
                txn.commit().await?;
                return Ok(Outcome::Redirect {
                    url: result_url(
                        &ctx,
                        &format!("error={}", ErrorCode::ConsentRequired.as_str()),
                    ),
                    cookies: Vec::new(),
                });
            }
            (LoginStage::Consent, Some(session))
        }
        None => (LoginStage::Password, None),
    };
    let binding = tx::browser_binding(&headers, &state.config)?;
    let id = tx::create(
        conn,
        tx::NewTx {
            tenant_id: tenant.id,
            client_app_id: client.id,
            req: &req,
            stage,
            session,
            binding: &binding,
        },
    )
    .await?;
    let origin = state.config.tenant_origin(&tenant.slug);
    Ok(Outcome::Redirect {
        url: format!("{origin}/login?tx={id}"),
        cookies: vec![cookie::set(&state.config, Kind::TxBinding, &binding)?],
    })
}

/// The pending request a user code names, with its still opted-in client.
async fn find(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    code: &str,
) -> anyhow::Result<Option<(device_authorizations::Model, applications::Model)>> {
    let Some(row) = device_flow::find_pending(conn, tenant_id, code).await? else {
        return Ok(None);
    };
    let client = applications::Entity::find_by_id(row.application_id)
        .filter(applications::Column::TenantId.eq(tenant_id))
        .one(conn)
        .await?
        .filter(|c| c.device_code_enabled);
    Ok(client.map(|c| (row, c)))
}

/// `{origin}/device?{query}` — where a device sign-in ends.
pub fn result_url(ctx: &Ctx<'_>, query: &str) -> String {
    let origin = ctx.state.config.tenant_origin(&ctx.tenant.slug);
    format!("{origin}/device?{query}")
}

/// Approves the device request with the session the browser now has;
/// `false` = it expired or was decided meanwhile. Runs on the completion's
/// transaction.
pub async fn approve(
    conn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    device_id: Uuid,
    client_app_id: Uuid,
    session: &sessions::Model,
) -> anyhow::Result<bool> {
    let decision = Decision::Approve {
        amr: &session.amr,
        auth_time: session.auth_time,
    };
    let user_id = session.user_id;
    if !device_flow::decide(conn, ctx.tenant.id, device_id, user_id, decision).await? {
        return Ok(false);
    }
    let details = json!({
        "device_authorization_id": device_id,
        "session_id": session.id,
    });
    record(
        conn,
        ctx,
        audit::EventType::DeviceCodeApprove,
        user_id,
        client_app_id,
        details,
    )
    .await?;
    Ok(true)
}

/// Denies the device request (the user declined, or the scopes need an
/// administrator's consent); the device's next poll gets `access_denied`.
pub async fn deny(
    conn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    device_id: Uuid,
    client_app_id: Uuid,
    user_id: Uuid,
    reason: &'static str,
) -> anyhow::Result<()> {
    if device_flow::decide(conn, ctx.tenant.id, device_id, user_id, Decision::Deny).await? {
        let details = json!({ "device_authorization_id": device_id, "reason": reason });
        record(
            conn,
            ctx,
            audit::EventType::DeviceCodeDeny,
            user_id,
            client_app_id,
            details,
        )
        .await?;
    }
    Ok(())
}

/// Denies the device request behind login transaction `tx`, if it has one
/// — on the transaction that just claimed it (`tx::take`), so the device
/// never keeps polling `authorization_pending` after the login is gone.
pub async fn deny_for(
    conn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    tx: &tx::LoadedTx,
    user_id: Uuid,
    reason: &'static str,
) -> anyhow::Result<()> {
    match tx.req.device {
        Some(device_id) => deny(conn, ctx, device_id, tx.row.application_id, user_id, reason).await,
        None => Ok(()),
    }
}

async fn record(
    conn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    event_type: audit::EventType,
    user_id: Uuid,
    client_app_id: Uuid,
    details: Value,
) -> anyhow::Result<()> {
    audit::record(
        conn,
        audit::Event {
            tenant_id: ctx.tenant.id,
            actor: audit::Actor::User(Some(user_id)),
            event_type,
            target: Some(audit::Target::Application(client_app_id)),
            outcome: AuditOutcome::Success,
            ip: ctx.ip,
            details,
        },
    )
    .await
}
