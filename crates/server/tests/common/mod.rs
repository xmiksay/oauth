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

/// A throwaway database. Keep it alive for the whole test: it is removed when
/// dropped.
pub struct TestDb {
    pub url: String,
    /// Name for a role a test creates ([`TestDb::login_role`]): roles are
    /// server-wide, so on a shared server it is unique and dropped with the database.
    role: String,
    _guard: Guard,
}

impl TestDb {
    /// Creates a LOGIN role without privileges beyond PUBLIC's and returns this
    /// database's URL connecting as it.
    pub async fn login_role(&self) -> String {
        let admin = sea_orm::Database::connect(&self.url)
            .await
            .expect("connect as admin");
        let role = &self.role;
        admin
            .execute_unprepared(&format!("CREATE ROLE \"{role}\" LOGIN PASSWORD '{role}'"))
            .await
            .expect("create login role");
        admin.close().await.expect("close admin connection");
        let mut url = url::Url::parse(&self.url).expect("test database URL");
        url.set_username(role).expect("URL takes a username");
        url.set_password(Some(role)).expect("URL takes a password");
        url.into()
    }
}

enum Guard {
    Container(Box<ContainerAsync<Postgres>>),
    Local { admin_url: String, name: String },
}

impl Drop for Guard {
    fn drop(&mut self) {
        let Guard::Local { admin_url, name } = self else {
            return;
        };
        let admin_url = admin_url.clone();
        // Separate statements: DROP DATABASE can't run in the implicit
        // transaction of a multi-statement query.
        let sql = [
            format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"),
            format!("DROP ROLE IF EXISTS \"{name}\""),
        ];
        // Drop runs inside the test's runtime, which can't be blocked on: use a
        // fresh one on its own thread. FORCE ends the test's pooled connections.
        // Each statement on its own, so a failed database drop still drops the
        // role; leftovers are swept by `make test-db-clean`.
        let errors = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime for dropping the test database");
            rt.block_on(async {
                let admin = match sea_orm::Database::connect(&admin_url).await {
                    Ok(admin) => admin,
                    Err(e) => return vec![e.to_string()],
                };
                let mut errors = Vec::new();
                for sql in &sql {
                    if let Err(e) = admin.execute_unprepared(sql).await {
                        errors.push(format!("{sql}: {e}"));
                    }
                }
                let _ = admin.close().await;
                errors
            })
        })
        .join()
        .unwrap_or_else(|_| vec!["cleanup thread panicked".into()]);
        for e in errors {
            eprintln!("test database {name} cleanup: {e}");
        }
    }
}

/// A fresh database: on the server `TEST_DATABASE_URL` points at (an admin
/// connection, e.g. `postgres://postgres@localhost:5432/postgres` — the Makefile
/// default), else in a throwaway Postgres 17 container (CI).
pub async fn start_postgres() -> TestDb {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(admin_url) if !admin_url.is_empty() => local_database(admin_url).await,
        _ => container().await,
    }
}

async fn local_database(admin_url: String) -> TestDb {
    let name = format!("oauth_it_{}", uuid::Uuid::now_v7().simple());
    let admin = sea_orm::Database::connect(&admin_url)
        .await
        .expect("connect to TEST_DATABASE_URL");
    let version = admin
        .query_one_raw(sea_orm::Statement::from_string(
            admin.get_database_backend(),
            "SELECT current_setting('server_version_num')::int AS v",
        ))
        .await
        .expect("query server version")
        .expect("one row")
        .try_get::<i32>("", "v")
        .expect("server_version_num");
    // CI runs Postgres 17: an older server's green proves nothing.
    assert!(
        version >= 170000,
        "TEST_DATABASE_URL: Postgres >= 17 required, got {version}"
    );
    // template0: nothing the developer added to template1 leaks into tests.
    admin
        .execute_unprepared(&format!(
            "CREATE DATABASE \"{name}\" TEMPLATE template0 ENCODING 'UTF8'"
        ))
        .await
        .expect("create test database");
    admin.close().await.expect("close admin connection");
    let mut url = url::Url::parse(&admin_url).expect("TEST_DATABASE_URL is a URL");
    url.set_path(&name);
    TestDb {
        url: url.into(),
        role: name.clone(),
        _guard: Guard::Local { admin_url, name },
    }
}

async fn container() -> TestDb {
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
        role: "noddl".into(),
        _guard: Guard::Container(Box::new(container)),
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
