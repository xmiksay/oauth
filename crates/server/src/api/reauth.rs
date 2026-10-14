//! Re-authentication for sensitive self-service changes: the current
//! password OR a fresh passkey assertion (`POST me/reauth/options`), so a
//! user who signs in with passkeys only can still manage their account.
//! Both count against the per-account sign-in rate limit.

use axum::extract::State;
use entity::{
    enums::{Outcome, WebauthnPurpose},
    users,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Caller, me::me};
use crate::{
    app::AppState,
    audit::{self, EventType, Target},
    authn::rate_limit,
    directory::password,
    error::{AppError, AppResult},
    passkey::{self, AssertionJson, Owner, PasskeyError, Scope, store},
};

/// Request bodies that need re-authentication embed these two fields:
/// exactly one must be present.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReauthBody {
    pub password: Option<String>,
    pub passkey: Option<AssertionJson>,
}

impl ReauthBody {
    pub async fn verify(
        &self,
        state: &AppState,
        caller: &Caller,
        user: &users::Model,
    ) -> AppResult<()> {
        verify(
            state,
            caller,
            user,
            self.password.as_deref(),
            self.passkey.as_ref(),
        )
        .await
    }
}

/// 400 unless exactly one proof is given; 403 when it is wrong; 429 when
/// over the account's limit.
pub async fn verify(
    state: &AppState,
    caller: &Caller,
    user: &users::Model,
    password: Option<&str>,
    passkey: Option<&AssertionJson>,
) -> AppResult<()> {
    match (password, passkey) {
        (Some(password), None) => verify_password(state, user, password).await,
        (None, Some(assertion)) => verify_passkey(state, caller, user, assertion).await,
        _ => Err(AppError::BadRequest(
            "re-authenticate with exactly one of password or passkey".into(),
        )),
    }
}

/// Counts one re-authentication attempt in the account's sign-in bucket
/// (shared with the login API); 429 when over the limit.
async fn count_attempt(state: &AppState, user: &users::Model) -> AppResult<()> {
    let key = rate_limit::user_key(user.id);
    let now = chrono::Utc::now();
    match rate_limit::hit(
        &state.db,
        user.tenant_id,
        &key,
        rate_limit::PER_ACCOUNT,
        now,
    )
    .await?
    {
        Ok(()) => Ok(()),
        Err(retry_after) => Err(AppError::RateLimited { retry_after }),
    }
}

/// The current password; 403 when wrong (or the user has none).
async fn verify_password(state: &AppState, user: &users::Model, candidate: &str) -> AppResult<()> {
    count_attempt(state, user).await?;
    let ok = match &user.password_hash {
        Some(phc) if candidate.len() <= password::MAX_PASSWORD_LEN * 4 => {
            password::verify(candidate, phc).await?
        }
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "the current password is incorrect".into(),
        ))
    }
}

async fn verify_passkey(
    state: &AppState,
    caller: &Caller,
    user: &users::Model,
    assertion: &AssertionJson,
) -> AppResult<()> {
    count_attempt(state, user).await?;
    let refused = || AppError::Forbidden("the passkey could not be verified".into());
    let assertion = assertion.decode().map_err(|_| refused())?;
    let credential =
        store::find_by_credential_id(&state.db, user.tenant_id, &assertion.credential_id).await?;
    let scope = Scope::User {
        purpose: WebauthnPurpose::Reauth,
        user_id: user.id,
    };
    let rp = passkey::rp(&state.config, &caller.tenant.slug);
    let result = passkey::verify_assertion(
        &state.db,
        &rp,
        user.tenant_id,
        &assertion,
        scope,
        credential,
        Owner::User(user.id),
    )
    .await;
    match result {
        Ok(_) => Ok(()),
        Err(PasskeyError::Internal(err)) => Err(err.into()),
        Err(err) => {
            if err.is_sign_count_regression() {
                // Committed on its own: the refused request rolls nothing back.
                audit::record(
                    &state.db,
                    audit::Event {
                        tenant_id: user.tenant_id,
                        actor: audit::Actor::User(Some(user.id)),
                        event_type: EventType::PasskeySignCountRegression,
                        target: Some(Target::User(user.id)),
                        outcome: Outcome::Failure,
                        ip: caller.ip,
                        details: json!({ "via": "reauth" }),
                    },
                )
                .await?;
            }
            Err(refused())
        }
    }
}

/// `POST me/reauth/options`: an assertion challenge for the caller's own
/// passkeys (409 when they have none).
pub async fn options(
    State(state): State<AppState>,
    caller: Caller,
) -> AppResult<axum::Json<Value>> {
    let user = me(&state, &caller).await?;
    let credentials = store::list(&state.db, user.tenant_id, user.id).await?;
    if credentials.is_empty() {
        return Err(AppError::Conflict("no passkey is registered".into()));
    }
    let scope = Scope::User {
        purpose: WebauthnPurpose::Reauth,
        user_id: user.id,
    };
    let challenge = passkey::challenge::issue(&state.db, user.tenant_id, scope).await?;
    let rp = passkey::rp(&state.config, &caller.tenant.slug);
    Ok(axum::Json(passkey::wire::request_options(
        &rp,
        &challenge,
        &credentials,
    )))
}
