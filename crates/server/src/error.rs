//! Application error type. Internal causes are logged server-side and never
//! sent to clients, which only see a stable error code and a safe message.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found")]
    NotFound,
    #[error("service unavailable")]
    Unavailable,
    #[error(transparent)]
    Database(#[from] sea_orm::DbErr),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
            Self::Database(_) | Self::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
            }
        }
    }

    fn client_message(&self) -> String {
        match self {
            Self::BadRequest(msg) => msg.clone(),
            Self::NotFound => "resource not found".into(),
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
        (status, Json(body)).into_response()
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

        let (status, _) = render(AppError::NotFound).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = render(AppError::Unavailable).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }
}
