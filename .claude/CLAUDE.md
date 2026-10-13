# oauth — project brief

Entra-like multi-tenant identity provider: OAuth 2.1 / OpenID Connect with
tenants, app registrations, delegated scopes + app roles, groups, consent and
directory roles. Rust (Axum, SeaORM, Postgres) backend + Vue 3 SPA served
same-origin. Repo: `github.com:xmiksay/oauth`.

- Architecture: [docs/architecture.md](../docs/architecture.md)
- Roadmap / milestones: [docs/roadmap.md](../docs/roadmap.md)

## Layout

| Path | What |
|---|---|
| `crates/server/` | bin `oauth` (`serve`, `bootstrap`) + lib `oauth_server` (all modules; integration tests use it) |
| `crates/entity/` | SeaORM entities (one file per table) + `enums.rs` |
| `crates/migration/` | `sea-orm-migration` Migrator (append-only, raw SQL) |
| `web/` | Vite + Vue 3 + TS + Tailwind + Pinia SPA (`/{t}/login`, `/{t}/myaccount`, `/{t}/admin`) |
| `deploy/k8s/deploy.yml` | ConfigMap, Deployment, Service, PodDisruptionBudget (Secret `oauth-secrets` created by hand) |
| `.github/workflows/ci.yml` | `make lint` + `make test` + `make web-build`, plus `docker build`, on PR and push to `main`; actions pinned by SHA |

## Commands (always via make; `CARGO_BUILD_JOBS=4` is exported)

| Target | Does |
|---|---|
| `make dev-db` | Postgres 17 via docker compose (creds in `.env.example`) |
| `make run` | `oauth serve`, loads `.env` |
| `make web-dev` | Vite dev server |
| `make build` / `make web-build` | release binary + SPA / SPA only |
| `make lint` | `cargo fmt --check`, clippy `-D warnings`, eslint, vue-tsc |
| `make fmt` | `cargo fmt` |
| `make test` | `test-unit` + `test-integration` + `web-test` |
| `make test-unit` | `cargo test --workspace --lib --bins` |
| `make test-integration` | `cargo test --workspace --test '*'` (testcontainers — Docker required) |
| `make docker` | build image (`IMAGE=` to override tag) |
| `make bootstrap ADMIN_EMAIL=… [RESET=1]` | migrate, then create `system` tenant + Global Admin (idempotent; `RESET=1` issues a new one-time password) |

Toolchains are pinned: `rust-toolchain.toml` (1.99.0) and `.nvmrc` (22). CI reads
both; bump them deliberately and together with any lint fallout.

## Environment

See `.env.example` (authoritative, commented). Required: `DATABASE_URL`,
`PUBLIC_URL`, `OAUTH_MASTER_KEY` (32 bytes base64). Optional with defaults:
`LISTEN_ADDR` (0.0.0.0:8080), `METRICS_ADDR` (0.0.0.0:9090), `LOG_FORMAT`
(text|json), `RUST_LOG`, `KEY_ROTATION_DAYS` (90), `KEY_PREPUBLISH_HOURS` (48),
`SESSION_TTL_HOURS` (24), `WEB_DIST_DIR` (web/dist), `COOKIE_SECURE` (true;
`false` only with an `http://` `PUBLIC_URL`), `TRUSTED_PROXY_HEADER` (unset).
Login API contract for the SPA: [docs/api/authn.md](../docs/api/authn.md). Parsed and validated in
`crates/server/src/config.rs`; adding a var means updating `.env.example`,
`deploy/k8s/deploy.yml` and this list.

## Conventions

- Errors: `anyhow` + `.context()` in CLI/startup code; HTTP handlers return
  `AppResult<T>` (`error.rs`). DB/internal errors are logged, never sent to clients.
- No `unwrap`/`expect`/`panic!`/indexing outside tests (`clippy::{unwrap_used,
  expect_used, panic, indexing_slicing}` are on workspace-wide; integration test
  crates allow them at crate level).
- Migrations are append-only and run on startup, all pending ones in ONE
  transaction holding `pg_advisory_xact_lock` — so they must be
  transaction-safe (no `CREATE INDEX CONCURRENTLY`).
- Metric labels must stay bounded (route templates, fixed enums) — never raw
  paths, tenant slugs, methods or user input.
- Every table except `tenants` carries `tenant_id`; children reference parents
  via composite `(tenant_id, id)` FKs so cross-tenant links are impossible.
  Secrets/tokens/codes are stored as SHA-256 hashes and compared in constant
  time; reversible secrets (signing keys, TOTP) are AES-256-GCM sealed with
  `OAUTH_MASTER_KEY` and an AAD binding them to their row (`keys::wrap`).
- Schema: enums are `text` + `CHECK` (not Postgres enum types — those can't be
  extended and used in one migration transaction); PKs are app-generated
  UUIDv7 (`Uuid::now_v7()`); timestamps `timestamptz`. Rationale in
  `crates/migration/src/lib.rs`.
- Service code (`directory`, `keys`) is plain async functions over
  `ConnectionTrait` / `TransactionTrait`; `directory` returns the typed
  `DirectoryError` (→ `AppError`: 400 / 409 / 404 / 500).
- Tenant slugs: `^[a-z0-9][a-z0-9-]{1,62}$` minus `directory::slug::RESERVED_SLUGS`
  — adding a root route means adding its first segment there.
- Application crypto goes through one provider: AWS-LC via `aws-lc-rs` for key
  generation, AES-256-GCM, SHA-256 and randomness, and as `jsonwebtoken`'s
  backend (`aws_lc_rs` + `use_pem`). (`ring` is still linked transitively by
  sqlx's rustls for DB TLS — not used by our code.) Don't add `rsa` /
  `p256` / `aes-gcm` / `rand` (the `rsa` crate has RUSTSEC-2023-0071); `cargo tree -i rsa` must find nothing. Only
  `argon2` (password hashing) sits outside it and is built with opt-level 3
  in dev so tests stay fast. Building `aws-lc-sys` needs a C compiler (no
  cmake).
- Never derive `Debug` on anything holding secret material: entities with
  hashes / sealed keys and `bootstrap::OneTimePassword` hand-write a
  redacting `Debug`. SeaORM still derives `Debug` on every `ActiveModel`, so
  never log (`?`/`{:?}`) an `ActiveModel` of `users`, `user_totp`,
  `user_recovery_codes`, `client_secrets`, `signing_keys`, `sessions`,
  `authorization_codes`, `refresh_tokens` or `opaque_access_tokens`.
- Bearer values (cookies, codes, tokens) come from `secret::random_token`
  and are stored only as `secret::hash`; unguessable handles from
  `secret::random_uuid` (not UUIDv7).
- Protocol errors: `oidc::error::OAuthError` (RFC 6749 JSON); login API:
  `authn::AuthnError`. Never redirect to a `redirect_uri` before it matched
  the client's registration.
- Background work goes in `jobs` behind `jobs::try_lock` (per-run
  `pg_try_advisory_xact_lock`) so replicas never double-run it.
- Resource apps must not expose scope values named like OIDC scopes
  (`openid profile email offline_access`): stored grants keep both in one
  list (`oidc::scope::split_stored`). Step 4's scope API must reject them.
- `identifier_uri` `api://X` is only valid when X is the app's own
  `client_id` (DB CHECK `applications_api_uri_is_own_client_id`, scheme
  matched case-insensitively); step 4's app API should validate it up front
  for a friendly 400 and reject a non-lowercase `api://` scheme.
- Cookies are `__Host-` prefixed (`__Host-oauth_sid_{tenant}`,
  `__Host-oauth_tx`, `Path=/`) — never add a `Domain` or a narrower `Path`.
- Writes that must be atomic with token issuance (code consume, refresh
  rotation, login completion) run in one DB transaction; keep new service
  code generic over `ConnectionTrait` so it can join one.
- Never log request query strings (they carry codes / hints / tx ids);
  `app::request_span` logs the route template.
- Each file ≤ 400 lines. Backend changes ship with unit tests (`#[cfg(test)]`)
  and integration tests (`crates/server/tests/`, in-process router + testcontainers).
- Branches `feat/m1a-*` per roadmap step, ff-only onto `main`; `make lint` and
  `make test` green before push.
