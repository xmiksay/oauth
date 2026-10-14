//! `oauth serve`: startup sequence and graceful shutdown.

use std::{net::SocketAddr, path::Path, sync::atomic::Ordering};

use anyhow::Context;
use axum::Router;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    app::{self, AppState},
    config::{Config, LogFormat},
    db, jobs, metrics,
};

pub fn init_tracing(format: LogFormat) -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,sqlx=warn"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().try_init(),
    }
    .map_err(|err| anyhow::anyhow!("initialising tracing: {err}"))
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    tracing::info!(?config, "starting oauth server");
    // rustls is built with both AWS-LC (ours, lettre) and ring (sqlx); make
    // AWS-LC the explicit default rather than leave it to each user. `Err`
    // only means a default is already in place.
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a rustls crypto provider was already set");
    }
    let metrics_handle = metrics::install()?;
    let db = db::connect(&config.database_url).await?;

    let app_listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("binding LISTEN_ADDR {}", config.listen_addr))?;
    let metrics_listener = TcpListener::bind(config.metrics_addr)
        .await
        .with_context(|| format!("binding METRICS_ADDR {}", config.metrics_addr))?;
    tracing::info!(addr = %config.listen_addr, metrics = %config.metrics_addr, "listening");

    let shutdown = CancellationToken::new();
    tokio::spawn(forward_shutdown_signal(shutdown.clone()));
    run_with(
        Listeners {
            app: app_listener,
            metrics: metrics_listener,
        },
        AppState::new(db, config.clone(), false),
        &config.web_dist_dir,
        metrics::router(metrics_handle),
        shutdown,
    )
    .await
}

pub struct Listeners {
    pub app: TcpListener,
    pub metrics: TcpListener,
}

/// Serves on already-bound listeners, then migrates and marks the state ready.
/// Process-global setup (recorder, signal handlers) stays in [`run`] so tests
/// can drive this directly.
pub async fn run_with(
    listeners: Listeners,
    state: AppState,
    web_dist: &Path,
    metrics_router: Router,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    // Serve before migrating: while a replica waits for the migration lock,
    // `/healthz` keeps it alive and `/readyz` keeps it out of the Service.
    // Connect info gives handlers the peer address (rate limiting).
    let app = axum::serve(
        listeners.app,
        app::router(state.clone(), web_dist).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown.clone().cancelled_owned());
    let metrics_srv = axum::serve(listeners.metrics, metrics_router)
        .with_graceful_shutdown(shutdown.clone().cancelled_owned());
    let servers = tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            let result = tokio::try_join!(async { app.await.context("app server") }, async {
                metrics_srv.await.context("metrics server")
            },);
            // If one server failed, stop the other instead of hanging on it.
            shutdown.cancel();
            result.map(|_| ())
        }
    });

    let migration = tokio::select! {
        result = db::migrate_and_reconcile(&state.db, &state.config) => Some(result),
        // Dropping the migration future rolls its transaction back.
        () = shutdown.cancelled() => None,
    };
    let result = match migration {
        None => {
            tracing::info!("stopping before migrations finished");
            join(servers).await
        }
        Some(Ok(())) => {
            state.migrated.store(true, Ordering::Release);
            tracing::info!("migrations applied; ready");
            // Jobs need the schema, so they start only now.
            let jobs = jobs::spawn(state.clone(), shutdown.clone());
            let result = join(servers).await;
            shutdown.cancel();
            if let Err(err) = jobs.await {
                tracing::warn!(error = %err, "background jobs task panicked");
            }
            result
        }
        Some(Err(err)) => {
            // Never linger unready forever: stop serving and exit non-zero.
            shutdown.cancel();
            if let Err(server_err) = join(servers).await {
                tracing::warn!(error = %server_err, "server error during shutdown");
            }
            Err(err)
        }
    };
    // Whatever ended the run, work handlers left running (e.g. a queued
    // password reset) finishes first.
    state.tasks.close();
    state.tasks.wait().await;
    result
}

async fn join(servers: JoinHandle<anyhow::Result<()>>) -> anyhow::Result<()> {
    servers.await.context("server task panicked")?
}

async fn forward_shutdown_signal(token: CancellationToken) {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "ctrl-c handler failed");
            std::future::pending::<()>().await;
        }
    };
    let sigterm = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "SIGTERM handler failed");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        () = ctrl_c => {},
        () = sigterm => {},
    }
    tracing::info!("shutdown signal received, draining connections");
    token.cancel();
}
