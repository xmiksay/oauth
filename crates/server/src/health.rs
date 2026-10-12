//! Kubernetes probes: `/healthz` = process alive, `/readyz` = able to serve.

use std::sync::atomic::Ordering;

use axum::{Router, extract::State, routing::get};

use crate::{
    app::AppState,
    error::{AppError, AppResult},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<AppState>) -> AppResult<&'static str> {
    if !state.migrated.load(Ordering::Acquire) {
        return Err(AppError::Unavailable);
    }
    state.db.ping().await.map_err(|err| {
        tracing::warn!(error = %err, "readiness: database ping failed");
        AppError::Unavailable
    })?;
    Ok("ok")
}
