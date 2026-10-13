//! Second factor: TOTP code or a one-time recovery code. Both count against
//! the same rate limits as passwords.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
};
use entity::enums::LoginStage;
use serde::Deserialize;

use super::{
    AuthnError, AuthnResult, JsonBody, Outcome, complete::proceed, ctx::Ctx, ip::ClientIp,
    password::limit, rate_limit, recovery, totp, tx,
};
use crate::{app::AppState, metrics, tenancy::Tenant};

/// RFC 8176: password + one-time code = multi-factor. Recovery codes are
/// one-time passwords too.
const MFA_AMR: [&str; 3] = ["pwd", "otp", "mfa"];

#[derive(Deserialize)]
pub struct CodeBody {
    code: String,
}

#[derive(Clone, Copy)]
enum Factor {
    Totp,
    Recovery,
}

async fn second_factor(
    state: AppState,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    tx_id: String,
    code: String,
    factor: Factor,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let conn = &state.db;
    let mut tx = tx::load_at(&ctx, &tx_id, LoginStage::Mfa).await?;
    let user = tx::user_of(conn, &tx).await?;
    limit(&ctx, &rate_limit::user_key(user.id)).await?;
    let ok = match factor {
        Factor::Totp => match totp::confirmed(conn, tenant.id, user.id).await? {
            Some(row) => totp::verify_for_user(conn, &state.config.master_key, &row, &code).await?,
            None => false,
        },
        Factor::Recovery => recovery::redeem(conn, tenant.id, user.id, &code).await?,
    };
    if !ok {
        metrics::login("mfa_failed");
        return Err(AuthnError::InvalidCode);
    }
    tx.row.amr = MFA_AMR.iter().map(|s| (*s).to_owned()).collect();
    let next = user
        .must_change_password
        .then_some(LoginStage::ChangePassword);
    proceed(&ctx, tx, LoginStage::Mfa, next, &user, false).await
}

pub async fn totp(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path((_, tx_id)): Path<(String, String)>,
    JsonBody(body): JsonBody<CodeBody>,
) -> AuthnResult<Outcome> {
    second_factor(state, tenant, ip, headers, tx_id, body.code, Factor::Totp).await
}

pub async fn recovery(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path((_, tx_id)): Path<(String, String)>,
    JsonBody(body): JsonBody<CodeBody>,
) -> AuthnResult<Outcome> {
    second_factor(
        state,
        tenant,
        ip,
        headers,
        tx_id,
        body.code,
        Factor::Recovery,
    )
    .await
}
