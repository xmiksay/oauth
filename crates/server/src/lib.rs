//! `oauth` — Entra-like multi-tenant OAuth 2.1 / OpenID Connect provider.

pub mod app;
pub mod bootstrap;
pub mod config;
pub mod db;
pub mod directory;
pub mod error;
pub mod health;
pub mod keys;
pub mod metrics;
pub mod serve;
pub mod spa;
