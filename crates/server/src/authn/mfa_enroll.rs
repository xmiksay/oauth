//! Forced enrolment (`mfa_enroll` stage): MFA is required for this sign-in
//! (`mfa_policy`) and the user, already past their first factor, has no
//! second one. They set up TOTP (`…/enroll/totp`, `…/enroll/totp/confirm`)
//! or a passkey (`…/enroll/passkey/options`, `…/enroll/passkey`); the new
//! factor's successful use makes the sign-in multi-factor, and it goes on
//! as after the MFA step. A confirmed TOTP answers with only the new
//! recovery codes (shown once) and the transaction waits at this stage
//! until `…/enroll/continue`: the code must not be issued (and expire)
//! while the user is still saving them.

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use entity::{
    enums::{LoginStage, NotifyEvent, Outcome as AuditOutcome, WebauthnPurpose},
    users,
};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    AuthnError, AuthnResult, JsonBody, Outcome,
    complete::proceed,
    ctx::Ctx,
    invite_passkey::registration_error,
    ip::ClientIp,
    mfa_policy,
    password::limit,
    rate_limit,
    tx::{self, LoadedTx},
};
use crate::{
    api::me_mfa,
    app::AppState,
    audit::{self, EventType},
    error::AppError,
    notify,
    oidc::error::no_store,
    passkey::{
        self, RegistrationJson, Scope,
        store::{self, NewCredential},
    },
    tenancy::Tenant,
};

/// Enrolment errors in login-API terms.
fn enroll_error(err: AppError) -> AuthnError {
    match err {
        AppError::BadRequest(_) => AuthnError::InvalidCode,
        AppError::Conflict(msg) => AuthnError::Conflict(msg),
        AppError::RateLimited { retry_after } => AuthnError::RateLimited { retry_after },
        AppError::NotFound => AuthnError::NotFound,
        other => AuthnError::Internal(anyhow::anyhow!("{other}")),
    }
}

/// The transaction at `mfa_enroll` and its user; `enrolled` = whether a
/// factor must already have been set up (`continue`) or must not (the
/// enrolment calls).
async fn load(ctx: &Ctx<'_>, tx_id: &str, enrolled: bool) -> AuthnResult<(LoadedTx, users::Model)> {
    let tx = tx::load_at(ctx, tx_id, LoginStage::MfaEnroll).await?;
    if mfa_policy::is_mfa(&tx.row.amr) != enrolled {
        return Err(AuthnError::WrongStep);
    }
    let user = tx::user_of(&ctx.state.db, &tx).await?;
    if user.disabled {
        return Err(AuthnError::AccountDisabled);
    }
    Ok((tx, user))
}

/// Audits the new factor and queues the "security info changed" notice on
/// the enrolment's transaction.
async fn record(
    conn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    user: &users::Model,
    event_type: EventType,
    details: Value,
    what: &str,
) -> anyhow::Result<()> {
    audit::record(
        conn,
        audit::Event {
            tenant_id: ctx.tenant.id,
            actor: audit::Actor::User(Some(user.id)),
            event_type,
            target: Some(audit::Target::User(user.id)),
            outcome: AuditOutcome::Success,
            ip: ctx.ip,
            details,
        },
    )
    .await?;
    let facts = notify::change(what);
    let config = &ctx.state.config;
    notify::event(
        conn,
        config,
        ctx.tenant,
        user,
        NotifyEvent::MfaChanged,
        &facts,
    )
    .await
}

/// The sign-in's MFA is complete (`tx.row.amr`): continue as after `mfa`.
async fn after_enrolment(ctx: &Ctx<'_>, tx: LoadedTx, user: &users::Model) -> AuthnResult<Outcome> {
    let next = user
        .must_change_password
        .then_some(LoginStage::ChangePassword);
    proceed(ctx, tx, LoginStage::MfaEnroll, next, user, false).await
}

/// `POST …/enroll/totp`: a new pending secret (replacing an unconfirmed
/// one), shown once.
pub async fn begin_totp(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
) -> AuthnResult<Response> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let (_, user) = load(&ctx, &tx_id, false).await?;
    // Each call replaces the pending secret (one the user may be scanning).
    limit(&ctx, &rate_limit::user_key(user.id)).await?;
    let key = &state.config.master_key;
    let view = me_mfa::start_enrollment(&state.db, key, &tenant.display_name, &user)
        .await
        .map_err(enroll_error)?;
    Ok(no_store(Json(view).into_response()))
}

#[derive(Deserialize)]
pub struct CodeBody {
    code: String,
}

/// `POST …/enroll/totp/confirm`: a current code activates the secret and
/// makes the sign-in multi-factor; it answers with the recovery codes only
/// (see the module docs).
pub async fn confirm_totp(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
    JsonBody(body): JsonBody<CodeBody>,
) -> AuthnResult<Response> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let (tx, user) = load(&ctx, &tx_id, false).await?;
    limit(&ctx, &rate_limit::user_key(user.id)).await?;
    let pending = me_mfa::pending_enrollment(&state.db, &user)
        .await
        .map_err(enroll_error)?;
    let txn = state.db.begin().await?;
    let key = &state.config.master_key;
    let codes = match me_mfa::activate(&txn, key, &user, &pending, &body.code).await {
        Ok(codes) => codes,
        Err(err) => {
            drop(txn);
            let details = json!({ "reason": "enroll_failed", "factor": "totp" });
            ctx.audit_sign_in(&state.db, Some(user.id), AuditOutcome::Failure, details)
                .await?;
            return Err(enroll_error(err));
        }
    };
    let details = json!({ "via": "sign_in" });
    let what = "authenticator app added";
    record(&txn, &ctx, &user, EventType::MfaTotpEnroll, details, what).await?;
    let amr = tx::with_second_factor(&tx.row.amr, "otp");
    tx::set_amr(&txn, tx.row.id, LoginStage::MfaEnroll, amr).await?;
    txn.commit().await?;
    let body = json!({ "recovery_codes": codes });
    Ok(no_store(Json(body).into_response()))
}

/// `POST …/enroll/continue`: after a TOTP enrolment's recovery codes were
/// acknowledged, the sign-in goes on.
pub async fn resume(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let (tx, user) = load(&ctx, &tx_id, true).await?;
    after_enrolment(&ctx, tx, &user).await
}

/// `POST …/enroll/passkey/options`: creation options for a new passkey.
pub async fn passkey_options(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
) -> AuthnResult<Response> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let (_, user) = load(&ctx, &tx_id, false).await?;
    // Each call stores a challenge row.
    limit(&ctx, &rate_limit::user_key(user.id)).await?;
    let handle = store::ensure_handle(&state.db, &user).await?;
    let scope = Scope::User {
        purpose: WebauthnPurpose::Register,
        user_id: user.id,
    };
    let challenge = passkey::challenge::issue(&state.db, tenant.id, scope).await?;
    let rp = passkey::rp(&state.config, &tenant.slug);
    let existing = store::list(&state.db, tenant.id, user.id).await?;
    let options = passkey::wire::creation_options(
        &rp,
        &tenant.display_name,
        &user,
        &handle,
        &challenge,
        &existing,
    );
    Ok(no_store(Json(options).into_response()))
}

#[derive(Deserialize)]
pub struct PasskeyBody {
    credential: RegistrationJson,
    name: Option<String>,
}

/// `POST …/enroll/passkey`: stores the new passkey (registered with user
/// verification, so it is the second factor of this sign-in).
pub async fn passkey(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
    JsonBody(body): JsonBody<PasskeyBody>,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let (mut tx, user) = load(&ctx, &tx_id, false).await?;
    limit(&ctx, &rate_limit::user_key(user.id)).await?;
    let registration = body
        .credential
        .decode()
        .map_err(|_| AuthnError::Invalid("malformed passkey response".into()))?;
    let name = store::name(body.name.as_deref()).map_err(registration_error)?;
    let rp = passkey::rp(&state.config, &tenant.slug);
    let registered =
        match passkey::verify_registration(&state.db, &rp, tenant.id, user.id, &registration).await
        {
            Ok(registered) => registered,
            Err(err) => {
                let details = json!({ "reason": err.reason(), "factor": "passkey" });
                ctx.audit_sign_in(&state.db, Some(user.id), AuditOutcome::Failure, details)
                    .await?;
                return Err(registration_error(err));
            }
        };
    let txn = state.db.begin().await?;
    let credential = store::insert(
        &txn,
        NewCredential {
            tenant_id: tenant.id,
            user_id: user.id,
            rp_id: &rp.id,
            registered: &registered,
            transports: registration.transports,
            name,
        },
    )
    .await
    .map_err(registration_error)?;
    let details = json!({
        "passkey_id": credential.id,
        "name": credential.name,
        "via": "sign_in",
    });
    let what = "passkey added";
    record(
        &txn,
        &ctx,
        &user,
        EventType::MfaPasskeyRegister,
        details,
        what,
    )
    .await?;
    // Stored with the credential: should `proceed` fail, a retry goes on
    // through `enroll/continue` instead of registering another passkey.
    tx.row.amr = tx::with_second_factor(&tx.row.amr, passkey::amr(&credential));
    tx::set_amr(&txn, tx.row.id, LoginStage::MfaEnroll, tx.row.amr.clone()).await?;
    txn.commit().await?;
    after_enrolment(&ctx, tx, &user).await
}
