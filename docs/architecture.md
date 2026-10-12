# Architecture

## Runtime

Single binary `oauth` (crate `crates/server`):

- `oauth serve` — config → tracing → DB pool → bind and start the HTTP
  listener (`LISTEN_ADDR`) + metrics listener (`METRICS_ADDR`) → run
  migrations → flip the `migrated` flag. Until then `/healthz` is 200 and
  `/readyz` 503, so a replica waiting on the migration lock stays alive but out
  of the Service. A failed migration shuts both listeners down and exits
  non-zero; SIGTERM / ctrl-c drains both listeners gracefully (and rolls back an
  in-flight migration).
- `oauth bootstrap --admin-email …` — creates the `system` tenant and its first
  Global Admin (idempotent). **Stub until M1a step 2** (exits with an error).

Migrations: all pending ones run in a single transaction that first takes
`pg_advisory_xact_lock(MIGRATION_LOCK_KEY)`, so concurrent replicas serialize
and the lock is released exactly on commit/rollback. Consequently migrations
must be transaction-safe (no `CREATE INDEX CONCURRENTLY`).

State lives only in PostgreSQL (sessions, codes, login transactions, rate
limits). Multiple replicas are safe: migrations serialize on the advisory lock,
background jobs (M1a step 3) elect a leader with `pg_try_advisory_lock`.

## HTTP surface (current)

| Route | Listener | Module |
|---|---|---|
| `GET /healthz` — process alive, no DB dependency | app | `health` |
| `GET /readyz` — migrations done + DB ping, else 503 | app | `health` |
| `/{tenant}/{login,myaccount,admin}[/…]` → `index.html` | app | `spa` |
| any other path → static file from `WEB_DIST_DIR`, else 404 | app | `spa` |
| `GET /metrics` — Prometheus text format | metrics | `metrics` |

A missing SPA build only logs a warning; SPA routes then return 404.

## Server modules (`crates/server/src/`)

Implemented:

| Module | Responsibility |
|---|---|
| `config` | Env parsing + validation (`Config::from_lookup` for tests); redacting `Debug` |
| `error` | `AppError` → JSON `{error, error_description}`; 5xx causes logged, never leaked |
| `app` | `AppState { db, migrated }` and router assembly (trace + metrics layers) |
| `db` | Pool connect; `migrate()` in one transaction holding `pg_advisory_xact_lock` |
| `health` | `/healthz`, `/readyz` |
| `metrics` | Global Prometheus recorder, `/metrics` router, `http_requests_total` + `http_request_duration_seconds`. Labels are bounded: `path` = route template (fallback → `unmatched`), `method` = standard verb or `other` |
| `spa` | `ServeDir` + history fallback for the three SPA areas |
| `serve` | `run` (process-global setup: recorder, binds, signals) → `run_with` (serve, then migrate, then ready; tested in `tests/serve.rs`), tracing init, graceful shutdown |

Planned (see [roadmap](roadmap.md)):

| Module | Responsibility |
|---|---|
| `tenancy` | Resolve tenant from path (M1a), later `Host` / custom domain (M1b) |
| `keys` | Per-tenant RS256/ES256 keys, AES-256-GCM wrapped with `OAUTH_MASTER_KEY`, rotation, JWKS |
| `authn` | Password (argon2id), TOTP, recovery codes, session cookie, login transactions, rate limit |
| `oidc/` | Discovery, authorize, token, userinfo, introspect, revoke, logout |
| `tokens/` | Claims builder, JWT (RFC 9068) / opaque access tokens, refresh rotation with family reuse detection |
| `consent` | User vs admin consent evaluation |
| `api/` | Management REST `/api/v1/tenants/{t}/…` and `me/…` |
| `authz` | Directory-role and app-role guards |
| `audit` | Append-only `audit_events` |
| `jobs` | TTL sweeper + key rotation (leader via `pg_try_advisory_lock`) |

## Crates

- `crates/entity` — SeaORM entities (empty until M1a step 2). Every table but
  `tenants` carries `tenant_id`.
- `crates/migration` — `Migrator`, append-only. Zero migrations so far.

## Frontend (`web/`)

One Vue 3 SPA with three areas — `/{t}/login`, `/{t}/myaccount`,
`/{t}/admin` — built to `web/dist` and served by the backend same-origin. Admin
and My Account are built-in public OIDC clients (code + PKCE via
`oidc-client-ts`) calling the management API with bearer tokens.

## Deployment

Multi-stage `Dockerfile` (node 22 → rust 1.99.0 → debian bookworm-slim, uid
10001). `deploy/k8s/deploy.yml`: ConfigMap, Deployment (2 replicas, liveness
`/healthz`, readiness `/readyz`, 5 s preStop sleep, no service-account token),
Service (http 8080, metrics 9090), PodDisruptionBudget (`minAvailable: 1`).
Secrets come from a hand-made Secret `oauth-secrets`. CI builds the image on
every PR (no push).
