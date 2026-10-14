// Test-only crate: helpers outside `#[test]` fns (e.g. in `common`) panic on
// setup failure by design, which clippy's in-tests allowances don't cover.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Drives the real startup sequence (`serve::run_with`) over TCP.
mod common;

use std::{net::SocketAddr, time::Duration};

use axum::Router;
use oauth_server::{
    app::AppState,
    db,
    serve::{self, Listeners},
};
use sea_orm::{ConnectionTrait, TransactionTrait};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;

async fn listeners() -> (Listeners, SocketAddr) {
    let app = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = app.local_addr().unwrap();
    (Listeners { app, metrics }, addr)
}

/// Minimal HTTP/1.1 GET over a real socket; returns the status code. Bounded,
/// because a bound-but-not-serving listener accepts TCP and then stays silent.
async fn http_status(addr: SocketAddr, path: &str) -> u16 {
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).await.unwrap();
        resp
    };
    let resp = tokio::time::timeout(Duration::from_secs(5), exchange)
        .await
        .unwrap_or_else(|_| panic!("GET {path}: no HTTP response within 5s"));
    resp.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("malformed response: {resp}"))
}

#[tokio::test]
async fn serves_before_migrating_and_turns_ready_after() {
    let pg = common::start_postgres().await;
    let conn = db::connect(&pg.url).await.unwrap();
    // Simulate another replica mid-migration.
    let holder = conn.begin().await.unwrap();
    common::advisory(&holder, "pg_advisory_lock").await;

    let (listeners, addr) = listeners().await;
    let shutdown = CancellationToken::new();
    let server = tokio::spawn({
        let state = AppState::new(
            conn.clone(),
            common::test_config(&pg.url, common::PUBLIC_URL),
            false,
        );
        let shutdown = shutdown.clone();
        async move {
            serve::run_with(
                listeners,
                state,
                common::no_web_dist(),
                Router::new(),
                shutdown,
            )
            .await
        }
    });

    assert_eq!(http_status(addr, "/healthz").await, 200);
    assert_eq!(http_status(addr, "/readyz").await, 503);

    common::advisory(&holder, "pg_advisory_unlock").await;
    holder.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while http_status(addr, "/readyz").await != 200 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("never became ready after the lock was released");

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("graceful shutdown hung")
        .unwrap()
        .unwrap();
}

/// Serves `config` until `/readyz` is 200, then shuts down cleanly.
async fn serve_until_ready(
    conn: sea_orm::DatabaseConnection,
    config: oauth_server::config::Config,
) {
    let (listeners, addr) = listeners().await;
    let shutdown = CancellationToken::new();
    let state = AppState::new(conn, config, false);
    let server = tokio::spawn(serve::run_with(
        listeners,
        state,
        common::no_web_dist(),
        Router::new(),
        shutdown.clone(),
    ));
    tokio::time::timeout(Duration::from_secs(20), async {
        while http_status(addr, "/readyz").await != 200 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("never became ready");
    shutdown.cancel();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn startup_rewrites_stale_builtin_redirect_uris_before_ready() {
    let (_pg, conn, config) = common::migrated_db().await;
    let new = oauth_server::directory::NewTenant {
        slug: "contoso",
        display_name: "Contoso",
    };
    let tenant = oauth_server::directory::create_tenant(&conn, &config, new)
        .await
        .unwrap();
    // As M1a stored them: path-based on the apex.
    conn.execute_unprepared(
        "UPDATE applications SET redirect_uris = ARRAY['https://id.example.test/contoso/admin/callback'] \
         WHERE client_id = 'admin-portal'",
    )
    .await
    .unwrap();
    serve_until_ready(conn.clone(), config).await;
    let app = common::mgmt::app_by_client_id(&conn, tenant.id, "admin-portal").await;
    assert_eq!(
        app.redirect_uris,
        [format!("{}/admin/callback", common::ORIGIN)]
    );
}

#[tokio::test]
async fn migration_failure_stops_the_server_with_an_error() {
    let pg = common::start_postgres().await;
    let admin = db::connect(&pg.url).await.unwrap();
    for sql in [
        "CREATE ROLE noddl LOGIN PASSWORD 'noddl'",
        // PG15+ already withholds CREATE on `public` from PUBLIC; be explicit.
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
    ] {
        admin.execute_unprepared(sql).await.unwrap();
    }
    let url = pg.url.replacen("postgres:postgres@", "noddl:noddl@", 1);
    let conn = db::connect(&url).await.unwrap();

    let (listeners, _) = listeners().await;
    let shutdown = CancellationToken::new();
    // Nobody cancels the token: run_with must stop on its own.
    let err = tokio::time::timeout(
        Duration::from_secs(20),
        serve::run_with(
            listeners,
            AppState::new(conn, common::test_config(&url, common::PUBLIC_URL), false),
            common::no_web_dist(),
            Router::new(),
            shutdown.clone(),
        ),
    )
    .await
    .expect("run_with kept serving after a failed migration")
    .unwrap_err();
    assert!(format!("{err:#}").contains("running migrations"), "{err:#}");
    assert!(shutdown.is_cancelled());
}
