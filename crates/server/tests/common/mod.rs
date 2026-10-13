//! Shared helpers for integration tests. Each test binary compiles this module
//! separately, so not every helper is used everywhere.
#![allow(dead_code)]

use std::{collections::HashMap, path::Path};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use oauth_server::{config::Config, db::MIGRATION_LOCK_KEY};
use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
};
use tower::ServiceExt;

/// A throwaway Postgres 17. Keep the container alive for the whole test: it is
/// removed when dropped.
pub struct TestDb {
    pub url: String,
    _container: ContainerAsync<Postgres>,
}

pub async fn start_postgres() -> TestDb {
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .expect("start postgres container (is Docker running?)");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("postgres host port");
    TestDb {
        url: format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres"),
        _container: container,
    }
}

pub async fn get(app: &Router, uri: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).expect("request"))
        .await
        .expect("infallible router");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

pub fn no_web_dist() -> &'static Path {
    Path::new("/nonexistent/web/dist")
}

/// Calls `func` (e.g. `pg_advisory_lock`) with the migration lock key.
pub async fn advisory(conn: &impl ConnectionTrait, func: &str) {
    conn.execute_raw(Statement::from_sql_and_values(
        conn.get_database_backend(),
        format!("SELECT {func}($1)"),
        [MIGRATION_LOCK_KEY.into()],
    ))
    .await
    .expect("advisory lock call");
}

pub const PUBLIC_URL: &str = "https://id.example.test";

/// Config pointing at `db_url` with a fixed master key and [`PUBLIC_URL`].
pub fn test_config(db_url: &str) -> Config {
    let env = HashMap::from([
        ("DATABASE_URL", db_url.to_owned()),
        ("PUBLIC_URL", PUBLIC_URL.to_owned()),
        // 32 bytes of 0x2a.
        (
            "OAUTH_MASTER_KEY",
            "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=".to_owned(),
        ),
    ]);
    Config::from_lookup(|k| env.get(k).cloned()).expect("test config")
}

/// Fresh Postgres, migrated, plus a config pointing at it.
pub async fn migrated_db() -> (TestDb, DatabaseConnection, Config) {
    let pg = start_postgres().await;
    let conn = oauth_server::db::connect(&pg.url).await.expect("connect");
    oauth_server::db::migrate(&conn).await.expect("migrate");
    let config = test_config(&pg.url);
    (pg, conn, config)
}
