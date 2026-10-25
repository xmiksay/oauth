//! Application error type. Internal causes are logged server-side and never
//! sent to clients, which only see a stable error code and a safe message.

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),
    /// Missing, invalid or expired bearer token (or one for another audience).
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// Authenticated, but not allowed to do this.
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("not found")]
    NotFound,
    /// The request body is over the size limit.
    #[error("payload too large")]
    PayloadTooLarge,
    /// The resource already exists (e.g. duplicate slug or email).
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("too many attempts")]
    RateLimited { retry_after: u64 },
    #[error("service unavailable")]
    Unavailable,
    #[error(transparent)]
    Database(#[from] sea_orm::DbErr),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    /// An axum body / JSON rejection, keeping a 413 a 413 (everything else is a 400).
    pub fn from_body_rejection(status: StatusCode, text: String) -> Self {
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            Self::PayloadTooLarge
        } else {
            Self::BadRequest(text)
        }
    }

    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "invalid_token"),
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Self::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
            Self::Database(_) | Self::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
            }
        }
    }

    fn client_message(&self) -> String {
        match self {
            Self::BadRequest(msg)
            | Self::Conflict(msg)
            | Self::Unauthorized(msg)
            | Self::Forbidden(msg) => msg.clone(),
            Self::NotFound => "resource not found".into(),
            Self::PayloadTooLarge => "request body too large".into(),
            Self::RateLimited { .. } => "too many attempts; retry later".into(),
            Self::Unavailable => "service temporarily unavailable".into(),
            Self::Database(_) | Self::Internal(_) => "internal server error".into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        // Only genuine faults are errors; 503 is an expected state (e.g. not
        // ready yet) and is logged where its cause is known.
        if matches!(self, Self::Database(_) | Self::Internal(_)) {
            tracing::error!(error = ?self, "request failed");
        }
        let body = json!({ "error": code, "error_description": self.client_message() });
        let mut response = (status, Json(body)).into_response();
        match self {
            // RFC 6750 §3: a bearer-protected resource names the scheme it wants.
            Self::Unauthorized(_) => {
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer error=\"invalid_token\""),
                );
            }
            Self::RateLimited { retry_after } => {
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
            }
            _ => {}
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;

    use super::*;

    async fn render(err: AppError) -> (StatusCode, serde_json::Value) {
        let resp = err.into_response();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn internal_errors_do_not_leak() {
        let (status, body) = render(anyhow::anyhow!("password=hunter2 leaked").into()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "server_error");
        assert!(!body.to_string().contains("hunter2"));
    }

    #[tokio::test]
    async fn database_errors_do_not_leak() {
        let err = sea_orm::DbErr::Custom("relation users_secret does not exist".into());
        let (status, body) = render(err.into()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.to_string().contains("users_secret"));
    }

    #[tokio::test]
    async fn client_errors_keep_their_message() {
        let (status, body) = render(AppError::BadRequest("missing tenant".into())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
        assert_eq!(body["error_description"], "missing tenant");

        let (status, body) = render(AppError::Conflict("slug taken".into())).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "conflict");
        assert_eq!(body["error_description"], "slug taken");

        let (status, body) = render(AppError::Forbidden("no".into())).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("forbidden"))
        );
        let resp = AppError::Unauthorized("expired".into()).into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"invalid_token\""
        );

        let (status, _) = render(AppError::NotFound).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = render(AppError::Unavailable).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn body_rejections_keep_a_413() {
        let err = AppError::from_body_rejection(StatusCode::PAYLOAD_TOO_LARGE, "len 9".into());
        let (status, body) = render(err).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["error"], "payload_too_large");
        assert_eq!(body["error_description"], "request body too large");

        let err = AppError::from_body_rejection(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json".into());
        let (status, body) = render(err).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error_description"], "json");
    }
}
