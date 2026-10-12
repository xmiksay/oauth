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
| `crates/server/` | bin `oauth` (`serve`, `bootstrap` — stub until M1a step 2) + lib `oauth_server` (all modules; integration tests use it) |
| `crates/entity/` | SeaORM entities |
| `crates/migration/` | `sea-orm-migration` Migrator (append-only) |
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
| `make bootstrap ADMIN_EMAIL=…` | create `system` tenant + first admin (stub until M1a step 2) |

Toolchains are pinned: `rust-toolchain.toml` (1.99.0) and `.nvmrc` (22). CI reads
both; bump them deliberately and together with any lint fallout.

## Environment

See `.env.example` (authoritative, commented). Required: `DATABASE_URL`,
`PUBLIC_URL`, `OAUTH_MASTER_KEY` (32 bytes base64). Optional with defaults:
`LISTEN_ADDR` (0.0.0.0:8080), `METRICS_ADDR` (0.0.0.0:9090), `LOG_FORMAT`
(text|json), `RUST_LOG`, `KEY_ROTATION_DAYS` (90), `KEY_PREPUBLISH_HOURS` (48),
`SESSION_TTL_HOURS` (24), `WEB_DIST_DIR` (web/dist). Parsed and validated in
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
- Every table except `tenants` carries `tenant_id`. Secrets/tokens/codes are stored
  as SHA-256 hashes and compared in constant time.
- Each file ≤ 400 lines. Backend changes ship with unit tests (`#[cfg(test)]`)
  and integration tests (`crates/server/tests/`, in-process router + testcontainers).
- Branches `feat/m1a-*` per roadmap step, ff-only onto `main`; `make lint` and
  `make test` green before push.
