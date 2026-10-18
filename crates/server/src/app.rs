//! Router assembly and shared request state.

use std::{
    path::Path,
    sync::{Arc, atomic::AtomicBool},
};

use axum::{
    Router,
    extract::{MatchedPath, Request},
    middleware,
};
use sea_orm::DatabaseConnection;
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;
use tower_http::trace::{DefaultOnFailure, TraceLayer};
use tracing::{Level, Span};

use crate::{
    api, authn, config::Config, headers, health, metrics, oidc, spa, telegram, telegram::BotApi,
    tenancy,
};

/// Detached handler jobs allowed in flight (beyond: dropped).
pub const MAX_DETACHED: usize = 64;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub config: Arc<Config>,
    /// Set once startup migrations finished; gates `/readyz`.
    pub migrated: Arc<AtomicBool>,
    /// Work a handler leaves running after answering (e.g. queueing a
    /// password reset); shutdown waits for it.
    pub tasks: TaskTracker,
    /// Caps how many such detached jobs may be in flight at once.
    pub detached: Arc<Semaphore>,
    /// Bot API client, when Telegram is configured.
    pub telegram: Option<BotApi>,
}

impl AppState {
    pub fn new(db: DatabaseConnection, mut config: Config, migrated: bool) -> Self {
        let telegram = config.telegram.as_ref().and_then(|t| {
            BotApi::new(t)
                .map_err(|err| {
                    tracing::error!(error = ?err, "Telegram client setup failed; Telegram is off");
                })
                .ok()
        });
        // One source of truth: everything asking `config.telegram_enabled()`
        // must agree with whether a client exists.
        if telegram.is_none() {
            config.telegram = None;
        }
        Self {
            db,
            config: Arc::new(config),
            migrated: Arc::new(AtomicBool::new(migrated)),
            tasks: TaskTracker::new(),
            detached: Arc::new(Semaphore::new(MAX_DETACHED)),
            telegram,
        }
    }
}

/// Request span without the query string: authorize / logout URLs carry
/// codes, `id_token_hint`s and transaction ids that must not reach logs.
/// The route template is used when there is one (it also hides
/// transaction ids and object ids in paths).
fn request_span(req: &Request) -> Span {
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| req.uri().path(), MatchedPath::as_str);
    tracing::info_span!("request", method = %req.method(), path = %path)
}

pub fn router(state: AppState, web_dist: &Path) -> Router {
    let [frame, csp, referrer] = headers::security_layers();
    // Everything but the probes is scoped to a tenant host (probes hit the
    // pod IP, so they must answer on any host).
    let tenant_scoped = Router::new()
        .merge(oidc::router(state.clone()))
        .merge(authn::router(state.clone()))
        .merge(api::router())
        .merge(telegram::webhook::router())
        .merge(spa::router(web_dist))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            tenancy::resolve_host,
        ));
    Router::new()
        .merge(health::router())
        .merge(tenant_scoped)
        // `layer` (not `route_layer`) so fallback traffic is counted too; axum
        // applies it per route, so `MatchedPath` is still visible inside.
        .layer(middleware::from_fn(metrics::track))
        // Handlers log real faults at ERROR via `AppError`; the trace layer
        // would otherwise log every 5xx (including expected `/readyz` 503s)
        // at ERROR a second time.
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(request_span)
                .on_failure(DefaultOnFailure::new().level(Level::WARN)),
        )
        .layer(frame)
        .layer(csp)
        .layer(referrer)
        .with_state(state)
}
