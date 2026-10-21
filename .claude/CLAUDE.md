# oauth — project brief

Entra-like multi-tenant identity provider: OAuth 2.1 / OpenID Connect with
tenants, app registrations, delegated scopes + app roles, groups, consent and
directory roles. Rust (Axum, SeaORM, Postgres) backend + Vue 3 SPA served
same-origin. Repo: `github.com:xmiksay/oauth`.

- Architecture: [docs/architecture.md](../docs/architecture.md), SPA: [docs/frontend.md](../docs/frontend.md),
  sign-in: [docs/authn.md](../docs/authn.md), passkeys: [docs/passkeys.md](../docs/passkeys.md),
  federation: [docs/federation.md](../docs/federation.md)
- Roadmap / milestones: [docs/roadmap.md](../docs/roadmap.md)
- Deployment / release: [docs/deploy.md](../docs/deploy.md)

## Layout

| Path | What |
|---|---|
| `crates/server/` | bin `oauth` (`serve`, `bootstrap`) + lib `oauth_server` (all modules; integration tests use it) |
| `crates/entity/` | SeaORM entities (one file per table) + `enums.rs` |
| `crates/migration/` | `sea-orm-migration` Migrator (append-only, raw SQL) |
| `web/` | Vite + Vue 3 + TS + Tailwind + Pinia SPA (`/` portal, `/login`, `/logout`, `/myaccount`, `/admin` on each tenant host); conventions below |
| `deploy/k8s/deploy.yml` | ConfigMap, Deployment, Service, PodDisruptionBudget, Ingress for apex + `*.` wildcard (TLS Secret `oauth-wildcard-tls` via cert-manager DNS-01; Secret `oauth-secrets` created by hand) |
| `.github/workflows/ci.yml` | `gate` (`make lint` + `make test` + `make web-build`) and `docker` (build only) on PR, push to `main` and `v*` tags; `publish` pushes to GHCR (`:main` + `:sha-<short>` from `main`, `:X.Y.Z` from `vX.Y.Z`, which must equal the workspace version, be on `main` and not be in GHCR yet; releases build without cache); `deploy-test` rolls the digest out to test.oauth.cz (`services/deployment/oauth-test`) over WireGuard. Actions pinned by SHA. Environments, secrets, release procedure: [docs/deploy.md](../docs/deploy.md) |

## Commands (always via make; `CARGO_BUILD_JOBS=4` is exported)

| Target | Does |
|---|---|
| `make dev-db` | Postgres 17 + Mailpit (SMTP :1025, inbox http://localhost:8025) via docker compose (creds in `.env.example`) |
| `make run` | `oauth serve`, loads `.env` |
| `make web-dev` | Vite dev server on `*.localhost:5173` proxying to :8080 with `Host` kept (needs `PUBLIC_URL=http://localhost:5173`, the `.env.example` default); open `http://system.localhost:5173/admin` |
| `make build` / `make web-build` | release binary + SPA / SPA only |
| `make lint` | `lint-rust` (`cargo fmt --check`, clippy `-D warnings`) + `lint-web` (eslint, vue-tsc) |
| `make fmt` | `cargo fmt` |
| `make test` | `test-unit` + `test-integration` + `web-test` |
| `make test-unit` | `cargo test --workspace --lib --bins` |
| `make test-integration` | `cargo test --workspace --test '*'` (testcontainers — Docker required) |
| `make docker` | build image (`IMAGE=` to override tag) |
| `make bootstrap ADMIN_EMAIL=… [RESET=1]` | migrate, then create `system` tenant + Global Admin (idempotent; `RESET=1` issues a new one-time password) |
| `make telegram-webhook` | `oauth telegram set-webhook`: register `{PUBLIC_URL}/telegram/webhook` + secret with the bot (loads `.env`) |

Toolchains are pinned: `rust-toolchain.toml` (1.99.0) and `.nvmrc` (22). CI reads
both; bump them deliberately and together with any lint fallout.

## Environment

See `.env.example` (authoritative, commented). Required: `DATABASE_URL`,
`PUBLIC_URL`, `OAUTH_MASTER_KEY` (32 bytes base64). Optional with defaults:
`LISTEN_ADDR` (0.0.0.0:8080), `METRICS_ADDR` (0.0.0.0:9090), `LOG_FORMAT`
(text|json), `RUST_LOG`, `KEY_ROTATION_DAYS` (90), `KEY_PREPUBLISH_HOURS` (48),
`SESSION_TTL_HOURS` (24), `WEB_DIST_DIR` (web/dist), `COOKIE_SECURE` (true;
`false` only with an `http://` `PUBLIC_URL`), `TRUSTED_PROXY_HEADER` (unset),
`SMTP_URL` + `SMTP_FROM` (both or neither; unset hides every email feature —
[docs/email.md](../docs/email.md)). `SMTP_URL` lives in the Secret, `SMTP_FROM`
in the ConfigMap. `TELEGRAM_BOT_TOKEN` + `TELEGRAM_WEBHOOK_SECRET` (Secret) +
`TELEGRAM_BOT_USERNAME` (ConfigMap): all three or none, unset hides every
Telegram feature; `TELEGRAM_API_URL` (https://api.telegram.org; http only to
loopback) — [docs/telegram.md](../docs/telegram.md).
Login API contract for the SPA: [docs/api/authn.md](../docs/api/authn.md); management API:
[docs/api/management.md](../docs/api/management.md) (+ [me.md](../docs/api/me.md), [identity_providers.md](../docs/api/identity_providers.md)). Env vars are parsed and validated in
`crates/server/src/config/` (`env.rs`, `smtp.rs`, `telegram.rs`, `public_url.rs`); adding a var means updating `.env.example`,
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
- Tenancy is by host only: tenant `t` lives at `t.{PUBLIC_URL host}[:port]`, its
  issuer is that origin (`Config::tenant_origin` / `issuer`; `PUBLIC_URL` is an origin,
  no path). `tenancy::resolve_host` gates every route but `/healthz` / `/readyz`
  (authority = absolute-form / `:authority` first, then `Host`, RFC 9112 §3.2.2;
  several `Host` headers → 400; default port normalised; unknown / disabled /
  other-port / nested hosts and tenants with a now-invalid slug → 404, apex `/` →
  system admin portal); never read `X-Forwarded-Host` / `Forwarded`. Startup
  (`db::migrate_and_reconcile`) refuses enabled tenants whose slug fails
  `slug::validate`. Routes have no tenant
  segment; take the `Tenant` extractor. Built-in SPA redirect URIs derive from
  `PUBLIC_URL`; `builtin_apps::reconcile_all` rewrites them at startup.
- Tenant slugs are DNS labels: `^[a-z0-9][a-z0-9-]{1,62}$` (DB CHECK), plus
  (`slug::validate`) no trailing `-` and no `--` as characters 3–4 (`xn--`),
  minus `directory::slug::RESERVED_SLUGS` (service host names like `www`,
  `mail`, `api`, and `system`). Older tenants may violate the newer rules:
  startup refuses any such tenant that is enabled, and re-enabling one through
  `PATCH /api/v1/tenants/{slug}` is a 400.
- Application crypto goes through one provider: AWS-LC via `aws-lc-rs` for key
  generation, AES-256-GCM, SHA-256 and randomness, and as `jsonwebtoken`'s
  backend (`aws_lc_rs` + `use_pem`). (`ring` is still linked transitively by
  sqlx's rustls for DB TLS — not used by our code.) Don't add `rsa` /
  `p256` / `aes-gcm` / `rand` (the `rsa` crate has RUSTSEC-2023-0071); `cargo tree -i rsa` and `cargo tree -i openssl-sys` must find nothing
  (WebAuthn is our own verifier, `webauthn`: AWS-LC + `ciborium`, no webauthn-rs; the
  Telegram client is reqwest `rustls-no-provider` handed an explicit AWS-LC
  `ClientConfig` with webpki roots — no native-tls). Only
  `argon2` (password hashing) sits outside it and is built with opt-level 3
  in dev so tests stay fast. Building `aws-lc-sys` needs a C compiler (no
  cmake).
- Never derive `Debug` on anything holding secret material: entities with
  hashes / sealed keys and `bootstrap::OneTimePassword` hand-write a
  redacting `Debug`. SeaORM still derives `Debug` on every `ActiveModel`, so
  never log (`?`/`{:?}`) an `ActiveModel` of `users`, `user_totp`,
  `user_recovery_codes`, `client_secrets`, `signing_keys`, `sessions`,
  `authorization_codes`, `refresh_tokens`, `opaque_access_tokens`, `outbox`,
  `email_tokens`, `known_devices`, `webauthn_challenges`, `telegram_links`,
  `telegram_link_codes`, `telegram_otps`, `identity_providers`,
  `user_identities` or `federation_states` (nor a `mail::Email`'s body, nor
  a `login_transactions` row's `pending_identity`).
  Never log a Bot API URL or a reqwest error's text (the URL carries the bot
  token: `telegram::api` logs error kinds only), a chat id or a message text. `webauthn_credentials` holds only public keys and credential ids, so
  its `Debug` is derived.
- Federation (`federation/`, [docs/federation.md](../docs/federation.md)):
  outbound HTTP only through `http::client` (no redirects, no proxy,
  timeouts) and `http::read_capped`; provider URLs pass `federation::urls`
  (https, loopback http only with `idp_allow_http_loopback`) and the
  federation client resolves through `federation::resolve::PublicOnly`
  (no private / loopback / link-local destinations outside dev). Changing an
  IdP's `issuer`, `client_id` or `discovery_url` (a repoint) unlinks all its
  identities (`identities::unlink_all`), bumps its `generation` and (issuer /
  discovery URL) drops the stored secret, in one transaction holding the row
  `FOR UPDATE`; anything writing on behalf of an upstream identity takes the
  row `FOR SHARE` via `idps::lock_current` at the verified generation. Never log
  upstream codes, tokens, ID tokens, states, nonces, PKCE verifiers, client
  secrets or the upstream authorization URL; failures are a fixed
  `federation::Failure` reason (audit `details.reason`), the user sees
  `upstream_failed`. Never link an account by email; JIT refuses an email
  that belongs to a user. The client secret is write-only (`has_secret`).
  The last-sign-in-method rule is `federation::identities::Methods` —
  anything removing a password, passkey or identity goes through it.
- Bearer values (cookies, codes, tokens) come from `secret::random_token`
  and are stored only as `secret::hash`; unguessable handles from
  `secret::random_uuid` (not UUIDv7).
- Protocol errors: `oidc::error::OAuthError` (RFC 6749 JSON); login API:
  `authn::AuthnError`. Never redirect to a `redirect_uri` before it matched
  the client's registration.
- Background work goes in `jobs` behind `jobs::try_lock` (per-run
  `pg_try_advisory_xact_lock`) so replicas never double-run it.
- Resource apps must not expose scope values named like OIDC scopes
  (`openid profile email offline_access`, any case) or `.default`: stored
  grants keep both in one list (`oidc::scope::split_stored`);
  `api::validate::scope_value` rejects them.
- `identifier_uri` `api://X` is only valid when X is the app's own
  `client_id` (DB CHECK `applications_api_uri_is_own_client_id`, scheme
  matched case-insensitively); `api::validate::identifier_uri` checks it up
  front (400) and rejects a non-lowercase `api://` scheme.
- Management API (`api`, contract [docs/api/management.md](../docs/api/management.md)):
  handlers take the `api::Caller` extractor (bearer token of the host's
  tenant for its `management-api`; `api::auth::SystemAdmin` for
  `/api/v1/tenants`, system host only), call `caller.require(Area, Access)`
  (matrix in `authz`) first, run the mutation in ONE transaction and record
  its audit event on that transaction (`caller.audit(&txn, …)`). Objects of
  other tenants are 404 (always filter by `caller.tenant_id()`); body-named
  objects that don't exist are 400 (`guard::referenced`). Lists paginate
  with `page::fetch` (UUIDv7 keyset). PATCH applies, audits and rule-checks
  only values that actually change (clients echo unchanged fields): most
  handlers use `api::set_changed`, `users.rs` / `groups.rs` compare against
  the loaded row directly. Changing a user goes through
  `guard::ensure_can_modify_user`; removing a GlobalAdmin's effect through
  `guard::ensure_not_last_global_admin`. App writes go through
  `app_rules` (`writable_app`, `ensure_may_manage_credentials` for secrets
  and redirect URIs, lifetime caps, per-app caps). Authorization
  (`caller.require…`) comes before validation and before `BEGIN`.
  Never trust authorization data frozen in a token: app-only roles and the
  delegated session are re-read per call (`api::auth`).
- Passkeys ([docs/passkeys.md](../docs/passkeys.md)): RP ID = tenant host without
  port, origin = `config.tenant_origin(slug)` exactly, UP + UV required,
  `attStmt` never trusted. Untrusted CBOR / JSON is size-bounded before
  parsing and must never panic. Challenges (`passkey::challenge`) are
  consumed first, on their own statement, by one `DELETE … RETURNING`; the
  counter is re-checked in the UPDATE that stores it. A user without a
  password keeps their last passkey (`passkey::store::remove`, under the
  user's row lock). Sensitive `me` calls take `api::reauth::ReauthBody`
  (password OR passkey), never a bare password.
- Audit: event types are the closed `audit::EventType` enum (add a variant,
  never a free string); `details` carry ids, names and changed field names
  only — never passwords, secrets, codes or tokens.
- Email: never send inline — render a `mail::templates` message and queue it
  with `mail::outbox::enqueue` / `mail::links::send` / `notify::event` on the
  action's own transaction; `jobs::outbox` delivers. Never log a body,
  recipient or link token. Link tokens are consumed via `mail::tokens::consume`
  (atomic, tenant-scoped); anything wrong with one is the same `invalid_token`.
  Public flows must not reveal whether an address exists (same status, body,
  rate-limit buckets keyed by address, not account).
- Telegram (`telegram`, [docs/telegram.md](../docs/telegram.md)): notices go
  through the outbox like email (`channel = telegram`, recipient = user id,
  chat looked up at send time; delivery = a `jobs::outbox::Courier`); only
  sign-in codes are sent inline (a login waits). The webhook lives on the apex
  only (`tenancy::resolve_host`), checks the secret token in constant time,
  acts only on private chats, answers 200 for anything authenticated and
  replies in its response body (never waits on the Bot API). "Has Telegram
  as a factor" comes from the link row alone (fail closed without a bot);
  whether the bot exists is `state.telegram` / `config.telegram`, which
  `AppState::new` keeps in agreement.
- Cookies are host-only and `__Host-` prefixed (`__Host-oauth_sid`,
  `__Host-oauth_tx`, `__Host-oauth_dev`, `Path=/`) — never add a `Domain` (it would share them
  across tenant hosts) or a narrower `Path`. The login API / logout POST
  CSRF check wants `Origin` = the tenant's origin.
- Writes that must be atomic with token issuance (code consume, refresh
  rotation, login completion) run in one DB transaction; keep new service
  code generic over `ConnectionTrait` so it can join one.
- Never log request query strings (they carry codes / hints / tx ids);
  `app::request_span` logs the route template.
- Each file ≤ 400 lines. Backend changes ship with unit tests (`#[cfg(test)]`)
  and integration tests (`crates/server/tests/`, in-process router + testcontainers).
- Branches `feat/m1a-*` / `feat/m1b-*` / `feat/m2-*` per roadmap step, ff-only onto `main`; `make lint` and
  `make test` green before push.

## Frontend conventions (`web/`)

Layout: `src/api/` (HTTP), `src/auth/oidc.ts` (UserManager settings, `SPA_SCOPE`),
`src/stores/` (Pinia: `auth`, `tenant`, `application`), `src/composables/`
(`usePagedList`, `useAction`, `usePrincipalNames`), `src/components/` (shared UI),
`src/areas/{portal,login,email,logout,myaccount,admin}/` (pages; `portal` = `/`; admin split into
`users/ groups/ apps/ access/ federation/`), `src/router/` (`admin.ts` = admin child routes),
`src/lib/format.ts` (pure helpers), `src/lib/navigate.ts` (full-page navigation, mocked in
tests), `src/test/helpers.ts` (fetch / UserManager fakes).

- All HTTP goes through `api/client.ts` (`request`, `ApiError`, `errorMessage`);
  management calls through `api/management.ts` (`authed` adds the bearer token
  from the auth store and re-authenticates on 401; `t.get/post/patch/del` take
  paths relative to `/api/v1/` of the page's host (`apiPath`), ``p`…` `` escapes path segments).
  The tenant is the first hostname label (`stores/tenant`), never a route param;
  the OIDC authority is `location.origin`. One module per resource
  group; response shapes in `api/types.ts`, matching `docs/api/management.md`.
- Auth state only in `stores/auth` (one `UserManager` per area, tokens in
  `sessionStorage`, never `localStorage`; one manager per area for the page's
  lifetime; refresh only through `accessToken()`, which is single-flight — never call
  `signinSilent` elsewhere or turn on `automaticSilentRenew`: refresh tokens rotate and
  reuse revokes the family). Routes needing sign-in carry
  `meta.area`; callback routes `meta.callback`. Don't call the API from a
  template expression — wrap it in a script function.
- **Secret-once rule:** one-time passwords, client secrets and recovery codes are
  held only in the showing component's local ref and rendered with
  `SecretOnceDialog`; cleared on close; never put in Pinia, storage or logs.
- PATCH only changed fields (`stores/application.changedFields`, defence in depth: the
  server ignores unchanged values too).
- Lists use `usePagedList` + `ListShell`; errors render through `ErrorAlert`
  (hides 401, phrases 403). Hide actions the caller's directory roles
  (`auth.canWriteUsers` / `canWriteApps` / `isGlobalAdmin`) can't perform.
- Tests: vitest + jsdom + `@vue/test-utils`, colocated `*.test.ts`. Don't return a
  value from `beforeEach` (vitest runs it as a cleanup hook).
