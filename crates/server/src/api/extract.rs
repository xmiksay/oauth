//! Axum extractors whose rejections render as `AppError` JSON instead of
//! axum's plain-text 400/404/422.

use axum::{
    extract::{FromRequest, FromRequestParts, OptionalFromRequest, Request},
    http::request::Parts,
};
use serde::de::DeserializeOwned;

use crate::error::AppError;

/// JSON request body (`Content-Type: application/json`).
pub struct Json<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Json<T> {
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, AppError> {
        <axum::Json<T> as FromRequest<S>>::from_request(req, state)
            .await
            .map(|axum::Json(value)| Self(value))
            .map_err(|rejection| AppError::BadRequest(rejection.body_text()))
    }
}

/// `Option<Json<T>>`: no `Content-Type` is `None` (a bodyless POST); a JSON
/// body is parsed as above.
impl<S: Send + Sync, T: DeserializeOwned> OptionalFromRequest<S> for Json<T> {
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Option<Self>, AppError> {
        <axum::Json<T> as OptionalFromRequest<S>>::from_request(req, state)
            .await
            .map(|body| body.map(|axum::Json(value)| Self(value)))
            .map_err(|rejection| AppError::BadRequest(rejection.body_text()))
    }
}

/// Query string.
pub struct Query<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for Query<T> {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, AppError> {
        axum::extract::Query::<T>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Query(value)| Self(value))
            .map_err(|rejection| AppError::BadRequest(rejection.body_text()))
    }
}

/// Path parameters; a malformed id names nothing, so it is a 404.
pub struct Path<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned + Send> FromRequestParts<S> for Path<T> {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, AppError> {
        axum::extract::Path::<T>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Path(value)| Self(value))
            .map_err(|_| AppError::NotFound)
    }
}
