//! Password step and the forced password change.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
};
use chrono::Utc;
use entity::{
    enums::{LoginStage, NotifyEvent, Outcome as AuditOutcome},
    users,
};
use sea_orm::TransactionTrait;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::OnceCell;

use super::{
    AuthnError, AuthnResult, JsonBody, Outcome, complete::proceed, ctx::Ctx, ip::ClientIp,
    rate_limit, totp, tx,
};
use crate::{
    app::AppState,
    audit,
    directory::{self, password},
    metrics, notify, passkey,
    tenancy::Tenant,
};

#[derive(Deserialize)]
pub struct PasswordBody {
    email: String,
    password: String,
}

/// A real argon2id hash of a random password, verified against when the
/// account doesn't exist (or has no password) so the response time doesn't
/// reveal which emails are registered.
async fn dummy_hash() -> anyhow::Result<&'static str> {
    static DUMMY: OnceCell<String> = OnceCell::const_new();
    DUMMY
        .get_or_try_init(|| async { password::hash(&password::generate_one_time()?).await })
        .await
        .map(String::as_str)
}

/// Counts an attempt against the IP and the account (`account_key`); 429
/// when either is over its limit.
pub(super) async fn limit(ctx: &Ctx<'_>, account_key: &str) -> AuthnResult<()> {
    let now = Utc::now();
    let buckets = [
        (rate_limit::ip_key(ctx.ip), rate_limit::PER_IP),
        (account_key.to_owned(), rate_limit::PER_ACCOUNT),
    ];
    for (key, limit) in buckets {
        if let Err(retry_after) =
            rate_limit::hit(&ctx.state.db, ctx.tenant.id, &key, limit, now).await?
        {
            metrics::login("rate_limited");
            return Err(AuthnError::RateLimited { retry_after });
        }
    }
    Ok(())
}

async fn check_password(user: Option<&users::Model>, candidate: &str) -> anyhow::Result<bool> {
    match user.and_then(|u| u.password_hash.as_deref()) {
        Some(phc) => password::verify(candidate, phc).await,
        None => {
            password::verify(candidate, dummy_hash().await?).await?;
            Ok(false)
        }
    }
}

pub async fn submit(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
    JsonBody(body): JsonBody<PasswordBody>,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let conn = &state.db;
    let mut tx = tx::load(&ctx, &tx_id).await?;
    let stage = tx.row.stage;
    if !matches!(stage, LoginStage::Password | LoginStage::Link) {
        return Err(AuthnError::WrongStep);
    }
    if body.password.len() > password::MAX_PASSWORD_LEN * 4 {
        return Err(AuthnError::InvalidCredentials);
    }
    // Format check before any lookup or bucket: the lookup can't match such
    // an email while the bucket would, which would tell registered and
    // unregistered accounts apart.
    if body.email.chars().any(char::is_control) {
        return Err(AuthnError::Invalid(
            "email must not contain control characters".into(),
        ));
    }
    let user = directory::find_user_by_email(conn, tenant.id, &body.email).await?;
    let account = match &user {
        Some(user) => rate_limit::user_key(user.id),
        None => rate_limit::email_key(conn, &body.email).await?,
    };
    limit(&ctx, &account).await?;
    if !check_password(user.as_ref(), &body.password).await? {
        metrics::login("invalid_credentials");
        let reason = if user.is_some() {
            "invalid_password"
        } else {
            "unknown_account"
        };
        let user_id = user.as_ref().map(|u| u.id);
        ctx.audit_sign_in(
            conn,
            user_id,
            AuditOutcome::Failure,
            json!({ "reason": reason }),
        )
        .await?;
        return Err(AuthnError::InvalidCredentials);
    }
    let Some(user) = user else {
        return Err(AuthnError::InvalidCredentials);
    };
    if user.disabled {
        metrics::login("disabled");
        let details = json!({ "reason": "disabled" });
        ctx.audit_sign_in(conn, Some(user.id), AuditOutcome::Failure, details)
            .await?;
        return Err(AuthnError::AccountDisabled);
    }
    let next = if has_second_factor(&state, tenant.id, user.id).await? {
        Some(LoginStage::Mfa)
    } else if user.must_change_password {
        Some(LoginStage::ChangePassword)
    } else {
        None
    };
    super::federation_pending::check(&ctx, &tx, &user).await?;
    tx.row.user_id = Some(user.id);
    tx.row.amr = vec!["pwd".to_owned()];
    tx.row.auth_time = Some(Utc::now().fixed_offset());
    proceed(&ctx, tx, stage, next, &user, false).await
}

/// Whether the user has a second factor, so a first factor alone doesn't
/// complete the sign-in.
pub(super) async fn has_second_factor(
    state: &AppState,
    tenant_id: uuid::Uuid,
    user_id: uuid::Uuid,
) -> anyhow::Result<bool> {
    Ok(totp::confirmed(&state.db, tenant_id, user_id)
        .await?
        .is_some()
        || passkey::store::count(&state.db, tenant_id, user_id).await? > 0
        || super::telegram::is_factor(state, tenant_id, user_id).await?)
}

#[derive(Deserialize)]
pub struct ChangeBody {
    new_password: String,
}

/// Rate-limited like the other steps: each attempt costs two argon2 runs.
/// Setting the password revokes the user's other sessions and refresh
/// tokens (`directory::set_password`).
pub async fn change(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    headers: HeaderMap,
    Path(tx_id): Path<String>,
    JsonBody(body): JsonBody<ChangeBody>,
) -> AuthnResult<Outcome> {
    let ctx = Ctx::new(&state, &tenant, ip, &headers);
    let conn = &state.db;
    let tx = tx::load_at(&ctx, &tx_id, LoginStage::ChangePassword).await?;
    let user = tx::user_of(conn, &tx).await?;
    limit(&ctx, &rate_limit::user_key(user.id)).await?;
    password::validate(&body.new_password)?;
    if check_password(Some(&user), &body.new_password).await? {
        return Err(AuthnError::Invalid(
            "the new password must differ from the current one".into(),
        ));
    }
    // The update and the revocation of the user's other sessions and tokens
    // commit together. (`set_password` hashes before its first statement, so
    // no row lock is held during argon2.)
    let txn = conn.begin().await?;
    directory::set_password(&txn, tenant.id, user.id, &body.new_password, false).await?;
    audit::record(
        &txn,
        audit::Event {
            tenant_id: tenant.id,
            actor: audit::Actor::User(Some(user.id)),
            event_type: audit::EventType::UserPasswordChange,
            target: Some(audit::Target::User(user.id)),
            outcome: AuditOutcome::Success,
            ip: ctx.ip,
            details: json!({ "via": "sign_in" }),
        },
    )
    .await?;
    let facts = notify::change("changed at sign-in");
    notify::event(
        &txn,
        &state.config,
        &tenant,
        &user,
        NotifyEvent::PasswordChanged,
        &facts,
    )
    .await?;
    txn.commit().await?;
    proceed(&ctx, tx, LoginStage::ChangePassword, None, &user, false).await
}
