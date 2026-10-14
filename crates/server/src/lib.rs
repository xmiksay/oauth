//! `oauth` — Entra-like multi-tenant OAuth 2.1 / OpenID Connect provider.

pub mod api;
pub mod app;
pub mod audit;
pub mod authn;
pub mod authz;
pub mod bootstrap;
pub mod config;
pub mod consent;
pub mod db;
pub mod directory;
pub mod error;
pub mod headers;
pub mod health;
pub mod jobs;
pub mod keys;
pub mod mail;
pub mod metrics;
pub mod notify;
pub mod oidc;
pub mod secret;
pub mod serve;
pub mod spa;
pub mod tenancy;
pub mod tokens;
