//! Passkey sign-in: `POST …/tx/{tx}/passkey/options` and `…/passkey`.
//!
//! At the password step it is passwordless: the credential names the user
//! (discoverable credential, user handle checked), and a user-verifying
//! passkey is multi-factor on its own, so MFA and the forced password
//! change are skipped. At the MFA step it is the second factor and must
//! belong to the user the password identified.

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use chrono::Utc;
use entity::{
    enums::{LoginStage, Outcome as AuditOutcome},
    users,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::json;

use super::{
    AuthnError, AuthnResult, JsonBody, Outcome, complete::proceed, ctx::Ctx, ip::ClientIp,
    password::limit, rate_limit, tx,
};
use crate::{
    app::AppState,
    metrics,
    oidc::error::no_store,
    passkey::{self, AssertionJson, Owner, PasskeyError, Scope, store},
    tenancy::Tenant,
    webauthn::b64_encode,
};

/// Stage of a transaction that accepts a passkey.
fn passkey_stage(stage: LoginStage) -> AuthnResult<()> {
    match stage {
        LoginStage::Password | LoginStage::Link | LoginStage::Mfa => Ok(()),
        _ => Err(AuthnError::WrongStep),
    }
}

pub async fn options(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
) -> AuthnResult<axum::response::Response> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let tx = tx::load(&ctx, &tx_id).await?;
    passkey_stage(tx.row.stage)?;
    // At the MFA step the user is known: offer their credentials, which
    // also serves authenticators without discoverable credentials.
    let allow = match (tx.row.stage, tx.row.user_id) {
        (LoginStage::Mfa, Some(user_id)) => store::list(&state.db, tenant.id, user_id).await?,
        _ => Vec::new(),
    };
    let scope = Scope::Login {
        tx_id: tx.row.id,
        user_id: tx.row.user_id.filter(|_| tx.row.stage == LoginStage::Mfa),
    };
    let challenge = passkey::challenge::issue(&state.db, tenant.id, scope).await?;
    let rp = passkey::rp(&state.config, &tenant.slug);
    let body = passkey::wire::request_options(&rp, &challenge, &allow);
    Ok(no_store(axum::response::IntoResponse::into_response(Json(
        body,
    ))))
}

/// A failed attempt: audited with the factor and a fixed reason code.
async fn fail(
    ctx: &Ctx<'_>,
    user_id: Option<uuid::Uuid>,
    stage: LoginStage,
    err: &PasskeyError,
) -> AuthnError {
    if let PasskeyError::Internal(_) = err {
        return AuthnError::Internal(anyhow::anyhow!("passkey verification failed: {err}"));
    }
    metrics::login(if stage == LoginStage::Mfa {
        "mfa_failed"
    } else {
        "invalid_credentials"
    });
    let details = json!({ "reason": err.reason(), "factor": "passkey" });
    if let Err(audit_err) = ctx
        .audit_sign_in(&ctx.state.db, user_id, AuditOutcome::Failure, details)
        .await
    {
        return AuthnError::Internal(audit_err);
    }
    AuthnError::InvalidCredentials
}

pub async fn submit(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
    JsonBody(body): JsonBody<AssertionJson>,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let conn = &state.db;
    let mut tx = tx::load(&ctx, &tx_id).await?;
    let stage = tx.row.stage;
    passkey_stage(stage)?;
    let assertion = body
        .decode()
        .map_err(|_| AuthnError::Invalid("malformed passkey response".into()))?;
    let credential =
        store::find_by_credential_id(conn, tenant.id, &assertion.credential_id).await?;
    let account = match (&credential, tx.row.user_id) {
        (_, Some(user_id)) => rate_limit::user_key(user_id),
        (Some(c), None) => rate_limit::user_key(c.user_id),
        (None, None) => format!("passkey:{}", b64_encode(&assertion.credential_id)),
    };
    limit(&ctx, &account).await?;
    let scope = Scope::Login {
        tx_id: tx.row.id,
        user_id: None,
    };
    let owner_user = match (stage, &credential) {
        (LoginStage::Mfa, _) => Some(tx::user_of(conn, &tx).await?),
        (_, Some(c)) => {
            users::Entity::find_by_id(c.user_id)
                .filter(users::Column::TenantId.eq(tenant.id))
                .one(conn)
                .await?
        }
        (_, None) => None,
    };
    let owner = match (stage, &owner_user) {
        (LoginStage::Mfa, Some(user)) => Owner::User(user.id),
        (_, user) => Owner::Handle(user.as_ref().and_then(|u| u.webauthn_handle.as_deref())),
    };
    let rp = passkey::rp(&state.config, &tenant.slug);
    let audited_user = owner_user.as_ref().map(|u| u.id);
    let verified =
        match passkey::verify_assertion(conn, &rp, tenant.id, &assertion, scope, credential, owner)
            .await
        {
            Ok(verified) => verified,
            Err(err) => return Err(fail(&ctx, audited_user, stage, &err).await),
        };
    let Some(user) = owner_user else {
        return Err(AuthnError::InvalidCredentials);
    };
    if user.disabled {
        metrics::login("disabled");
        let details = json!({ "reason": "disabled", "factor": "passkey" });
        ctx.audit_sign_in(conn, Some(user.id), AuditOutcome::Failure, details)
            .await?;
        return Err(AuthnError::AccountDisabled);
    }
    super::federation_pending::check(&ctx, &tx, &user).await?;
    let kind = passkey::amr(&verified.credential).to_owned();
    let (amr, next) = if stage == LoginStage::Mfa {
        let next = user
            .must_change_password
            .then_some(LoginStage::ChangePassword);
        (tx::with_second_factor(&tx.row.amr, &kind), next)
    } else {
        tx.row.user_id = Some(user.id);
        tx.row.auth_time = Some(Utc::now().fixed_offset());
        (vec![kind, "user".to_owned(), "mfa".to_owned()], None)
    };
    tx.row.amr = amr;
    proceed(&ctx, tx, stage, next, &user, false).await
}

/// The factors the step view offers (`factors`).
pub async fn factors(state: &AppState, tx: &tx::LoadedTx) -> AuthnResult<Vec<&'static str>> {
    Ok(match (tx.row.stage, tx.row.user_id) {
        (LoginStage::Password | LoginStage::Link, _) => vec!["password", "passkey"],
        (LoginStage::Mfa, Some(user_id)) => {
            let tenant_id = tx.row.tenant_id;
            let mut out = Vec::new();
            if crate::authn::totp::confirmed(&state.db, tenant_id, user_id)
                .await?
                .is_some()
            {
                out.extend(["totp", "recovery"]);
            }
            if store::count(&state.db, tenant_id, user_id).await? > 0 {
                out.push("passkey");
            }
            // Without a bot the factor can't work; it is offered only when
            // nothing else is, and then answers `telegram_unavailable`, so
            // the user learns why the step is stuck.
            if super::telegram::is_factor(state, tenant_id, user_id).await?
                && (state.telegram.is_some() || out.is_empty())
            {
                out.push("telegram");
            }
            out
        }
        _ => Vec::new(),
    })
}
