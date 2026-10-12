//! Schema migrations. Append-only: never edit a migration that has shipped,
//! add a new one instead.
//!
//! The server applies all pending migrations in ONE transaction (holding a
//! transaction-scoped advisory lock, see `oauth_server::db::migrate`), so a
//! migration must be transaction-safe: no `CREATE INDEX CONCURRENTLY`, no
//! `ALTER TYPE … ADD VALUE` followed by use of the new value in the same run.

pub use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![]
    }
}
