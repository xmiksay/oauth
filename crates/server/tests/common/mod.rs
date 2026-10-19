//! Shared helpers for integration tests. Each test binary compiles this module
//! separately, so not every helper is used everywhere.
#![allow(dead_code)]

pub mod authenticator;
pub mod browser;
pub mod federation;
pub mod flow;
pub mod mail;
pub mod mgmt;
pub mod passkeys;
pub mod seed;
pub mod telegram;
pub mod upstream;

use std::{collections::HashMap, path::Path};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderValue, Request, StatusCode, header},
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
    let mut req = Request::get(uri).body(Body::empty()).expect("request");
    default_host(&mut req);
    let resp = app.clone().oneshot(req).await.expect("infallible router");
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
/// Host and origin (= issuer) of the fixture tenant `contoso`.
pub const HOST: &str = "contoso.id.example.test";
pub const ORIGIN: &str = "https://contoso.id.example.test";

/// Absolute URL of `path` on tenant `slug`'s host.
pub fn at(slug: &str, path: &str) -> String {
    format!("https://{slug}.id.example.test{path}")
}

/// A request with neither an absolute URI nor a `Host` goes to [`HOST`],
/// as a browser on the fixture tenant's pages would send it.
pub fn default_host(req: &mut Request<Body>) {
    if req.uri().authority().is_none() && !req.headers().contains_key(header::HOST) {
        req.headers_mut()
            .insert(header::HOST, HeaderValue::from_static(HOST));
    }
}

/// Config pointing at `db_url` with a fixed master key and `public_url`
/// (normally [`PUBLIC_URL`]); `Err` when the config is rejected.
pub fn try_config(db_url: &str, public_url: &str) -> anyhow::Result<Config> {
    config_with(db_url, public_url, &[])
}

/// [`try_config`] plus `extra` variables.
pub fn config_with(
    db_url: &str,
    public_url: &str,
    extra: &[(&'static str, &str)],
) -> anyhow::Result<Config> {
    let mut env = HashMap::from([
        ("DATABASE_URL", db_url.to_owned()),
        ("PUBLIC_URL", public_url.to_owned()),
        // 32 bytes of 0x2a.
        (
            "OAUTH_MASTER_KEY",
            "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=".to_owned(),
        ),
    ]);
    env.extend(extra.iter().map(|(k, v)| (*k, (*v).to_owned())));
    Config::from_lookup(|k| env.get(k).cloned())
}

/// SMTP settings for email-enabled fixtures (nothing listens there: tests
/// deliver through a capturing mailer).
pub const SMTP_ENV: [(&str, &str); 2] = [
    ("SMTP_URL", "smtp://127.0.0.1:1"),
    ("SMTP_FROM", "noreply@id.example.test"),
];

pub fn test_config(db_url: &str, public_url: &str) -> Config {
    try_config(db_url, public_url).expect("test config")
}

/// Fresh Postgres, migrated, plus a config pointing at it.
pub async fn migrated_db() -> (TestDb, DatabaseConnection, Config) {
    migrated_db_with(&[]).await
}

pub async fn migrated_db_with(
    extra: &[(&'static str, &str)],
) -> (TestDb, DatabaseConnection, Config) {
    let pg = start_postgres().await;
    let conn = oauth_server::db::connect(&pg.url).await.expect("connect");
    oauth_server::db::migrate(&conn).await.expect("migrate");
    let config = config_with(&pg.url, PUBLIC_URL, extra).expect("test config");
    (pg, conn, config)
}
