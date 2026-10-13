//! OAuth 2.0 / OIDC protocol errors (RFC 6749 §4.1.2.1 / §5.2, RFC 6750 §3,
//! OIDC Core §3.1.2.6). Internal causes are logged, never sent.

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

/// Closed set: also the label values of `oauth_token_errors_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
    InvalidScope,
    AccessDenied,
    LoginRequired,
    ConsentRequired,
    RequestNotSupported,
    InvalidToken,
    InsufficientScope,
    ServerError,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::RequestNotSupported => "request_not_supported",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
            Self::ServerError => "server_error",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::InvalidClient | Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::InsufficientScope => StatusCode::FORBIDDEN,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

#[derive(Debug)]
pub struct OAuthError {
    pub code: ErrorCode,
    pub description: String,
    /// The client tried HTTP Basic: a 401 must then challenge with `Basic`.
    pub basic_challenge: bool,
    internal: Option<anyhow::Error>,
}

pub type OAuthResult<T> = Result<T, OAuthError>;

impl OAuthError {
    pub fn new(code: ErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
            basic_challenge: false,
            internal: None,
        }
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, description)
    }

    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidGrant, description)
    }

    pub fn invalid_token(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidToken, description)
    }
}

impl From<anyhow::Error> for OAuthError {
    fn from(err: anyhow::Error) -> Self {
        Self {
            code: ErrorCode::ServerError,
            description: "internal server error".into(),
            basic_challenge: false,
            internal: Some(err),
        }
    }
}

impl From<sea_orm::DbErr> for OAuthError {
    fn from(err: sea_orm::DbErr) -> Self {
        anyhow::Error::new(err).into()
    }
}

/// Token-endpoint responses must never be cached (RFC 6749 §5.1).
pub fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        if let Some(err) = &self.internal {
            tracing::error!(error = ?err, "oauth request failed");
        }
        let code = self.code;
        let body = json!({ "error": code.as_str(), "error_description": self.description });
        let mut response = (code.status(), Json(body)).into_response();
        let challenge = match code {
            ErrorCode::InvalidClient if self.basic_challenge => Some(r#"Basic realm="oauth""#),
            ErrorCode::InvalidToken => Some(r#"Bearer error="invalid_token""#),
            ErrorCode::InsufficientScope => Some(r#"Bearer error="insufficient_scope""#),
            _ => None,
        };
        if let Some(challenge) = challenge {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(challenge),
            );
        }
        no_store(response)
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;

    use super::*;

    #[tokio::test]
    async fn renders_rfc6749_json_without_internals() {
        let resp = OAuthError::from(anyhow::anyhow!("db password=x")).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "server_error");
        assert!(!body.to_string().contains("password"));
    }

    #[test]
    fn statuses_and_challenges() {
        let mut err = OAuthError::new(ErrorCode::InvalidClient, "bad");
        err.basic_challenge = true;
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));
        let resp = OAuthError::invalid_grant("x").into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(!resp.headers().contains_key(header::WWW_AUTHENTICATE));
        let resp = OAuthError::invalid_token("x").into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
