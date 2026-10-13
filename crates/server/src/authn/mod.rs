//! Interactive sign-in: the login JSON API the SPA (`/{t}/login?tx=…`)
//! drives, sessions, second factors and rate limiting. Contract documented
//! in `docs/api/authn.md`.
//!
//! CSRF model: every non-GET call must be `Content-Type: application/json`
//! (not sendable cross-site without a CORS preflight, which we never grant)
//! AND carry an `Origin` equal to `PUBLIC_URL`'s origin.

mod complete;
pub mod cookie;
mod ctx;
pub mod ip;
mod mfa;
mod password;
pub mod rate_limit;
pub mod recovery;
pub mod session;
pub mod totp;
pub mod tx;

use axum::{
    Json, Router,
    extract::{FromRequest, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::{
    app::AppState, directory::DirectoryError, error::AppError, headers::content_type_is,
    oidc::error::no_store,
};

pub use complete::{evaluate_consent, force_consent};

pub fn router(state: AppState) -> Router<AppState> {
    const TX: &str = "/{tenant}/api/authn/tx/{tx}";
    Router::new()
        .route(TX, get(tx::get))
        .route(&format!("{TX}/password"), post(password::submit))
        .route(&format!("{TX}/totp"), post(mfa::totp))
        .route(&format!("{TX}/recovery"), post(mfa::recovery))
        .route(&format!("{TX}/change-password"), post(password::change))
        .route(&format!("{TX}/consent"), post(complete::consent))
        .route_layer(middleware::from_fn_with_state(state, csrf))
}

/// CSRF guard for state-changing browser calls (also used by
/// `POST /{t}/oauth2/logout`).
pub(crate) async fn csrf(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD) {
        return next.run(req).await;
    }
    if !content_type_is(req.headers(), "application/json") {
        return AuthnError::Invalid("Content-Type must be application/json".into()).into_response();
    }
    let origin_ok = req
        .headers()
        .get(header::ORIGIN)
        .is_some_and(|o| o.as_bytes() == state.config.public_origin().as_bytes());
    if !origin_ok {
        return AuthnError::Csrf.into_response();
    }
    next.run(req).await
}

/// `Json` whose rejections (malformed body, wrong fields) render as our
/// JSON `invalid_request` instead of axum's plain-text 400/422.
pub struct JsonBody<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for JsonBody<T> {
    type Rejection = AuthnError;

    async fn from_request(req: Request, state: &S) -> Result<Self, AuthnError> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| AuthnError::Invalid(rejection.body_text()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthnError {
    /// Deliberately vague: never says whether the account exists.
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("invalid code")]
    InvalidCode,
    /// Only reported after the correct password was presented.
    #[error("account disabled")]
    AccountDisabled,
    #[error("this step is not expected now")]
    WrongStep,
    #[error("too many attempts")]
    RateLimited { retry_after: u64 },
    #[error("cross-site request rejected")]
    Csrf,
    #[error("login transaction not found or expired")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<sea_orm::DbErr> for AuthnError {
    fn from(err: sea_orm::DbErr) -> Self {
        Self::Internal(err.into())
    }
}

impl From<DirectoryError> for AuthnError {
    fn from(err: DirectoryError) -> Self {
        match err {
            DirectoryError::Invalid(msg) => Self::Invalid(msg),
            DirectoryError::Internal(err) => Self::Internal(err),
            other => Self::Internal(anyhow::anyhow!("unexpected directory error: {other}")),
        }
    }
}

impl From<AppError> for AuthnError {
    fn from(err: AppError) -> Self {
        match err {
            AppError::NotFound => Self::NotFound,
            other => Self::Internal(anyhow::anyhow!("{other}")),
        }
    }
}

impl IntoResponse for AuthnError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::InvalidCode => (StatusCode::UNAUTHORIZED, "invalid_code"),
            Self::AccountDisabled => (StatusCode::FORBIDDEN, "account_disabled"),
            Self::WrongStep => (StatusCode::CONFLICT, "wrong_step"),
            Self::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Csrf => (StatusCode::FORBIDDEN, "csrf_rejected"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Internal(err) => {
                tracing::error!(error = ?err, "login request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
            }
        };
        let description = match &self {
            Self::Internal(_) => "internal server error".to_owned(),
            other => other.to_string(),
        };
        let body = json!({ "error": code, "error_description": description });
        let mut response = no_store((status, Json(body)).into_response());
        if let Self::RateLimited { retry_after } = self
            && let Ok(value) = HeaderValue::from_str(&retry_after.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

/// Result of a login API call: the next step to render, or where to send
/// the browser (`{ "redirect": … }`), possibly setting the session cookie.
pub enum Outcome {
    Step(Value),
    Redirect {
        url: String,
        cookies: Vec<HeaderValue>,
    },
}

impl IntoResponse for Outcome {
    fn into_response(self) -> Response {
        match self {
            Self::Step(view) => no_store(Json(view).into_response()),
            Self::Redirect { url, cookies } => {
                let mut response = no_store(Json(json!({ "redirect": url })).into_response());
                for cookie in cookies {
                    response.headers_mut().append(header::SET_COOKIE, cookie);
                }
                response
            }
        }
    }
}

pub type AuthnResult<T> = Result<T, AuthnError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_sets_retry_after() {
        let resp = AuthnError::RateLimited { retry_after: 42 }.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers()[header::RETRY_AFTER], "42");
    }
}
