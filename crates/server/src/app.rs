//! Router assembly and shared request state.

use std::{
    path::Path,
    sync::{Arc, atomic::AtomicBool},
};

use axum::{Router, middleware};
use sea_orm::DatabaseConnection;
use tower_http::trace::{DefaultOnFailure, TraceLayer};
use tracing::Level;

use crate::{health, metrics, spa};

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    /// Set once startup migrations finished; gates `/readyz`.
    pub migrated: Arc<AtomicBool>,
}

impl AppState {
    pub fn new(db: DatabaseConnection, migrated: bool) -> Self {
        Self {
            db,
            migrated: Arc::new(AtomicBool::new(migrated)),
        }
    }
}

pub fn router(state: AppState, web_dist: &Path) -> Router {
    Router::new()
        .merge(health::router())
        .merge(spa::router(web_dist))
        // `layer` (not `route_layer`) so fallback traffic is counted too; axum
        // applies it per route, so `MatchedPath` is still visible inside.
        .layer(middleware::from_fn(metrics::track))
        // Handlers log real faults at ERROR via `AppError`; the trace layer
        // would otherwise log every 5xx (including expected `/readyz` 503s)
        // at ERROR a second time.
        .layer(TraceLayer::new_for_http().on_failure(DefaultOnFailure::new().level(Level::WARN)))
        .with_state(state)
}
