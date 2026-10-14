# Architecture

## Runtime

Single binary `oauth` (crate `crates/server`):

- `oauth serve` — config → tracing → DB pool → bind and start the HTTP
  listener (`LISTEN_ADDR`) + metrics listener (`METRICS_ADDR`) → run migrations and
  `builtin_apps::reconcile_all` → flip the `migrated` flag → start jobs. Until then `/healthz` is 200 and
  `/readyz` 503, so a replica waiting on the migration lock stays alive but out
  of the Service. A failed migration shuts both listeners down and exits
  non-zero; SIGTERM / ctrl-c drains both listeners gracefully (and rolls back an
  in-flight migration).
- `oauth bootstrap --admin-email … [--display-name …] [--reset-password]` —
  runs migrations, then (in one transaction holding a dedicated advisory lock,
  so concurrent runs serialize) creates the `system` tenant if missing and the
  admin if missing, ensures the admin holds `GlobalAdmin`, and prints a
  one-time password (`must_change_password = true`) to stdout. An existing
  admin's password is only replaced with `--reset-password`. Exit 0 either way.

Migrations: all pending ones run in a single transaction that first takes
`pg_advisory_xact_lock(MIGRATION_LOCK_KEY)` (replicas serialize; released exactly on
commit/rollback), so they must be transaction-safe (no `CREATE INDEX CONCURRENTLY`).

State lives only in PostgreSQL (sessions, codes, login transactions, rate
limits). Multiple replicas are safe: migrations serialize on the advisory lock,
background jobs run each tick inside a transaction holding
`pg_try_advisory_xact_lock(job key)` — one replica works, the others skip.

### Background jobs (`jobs`)

Spawned by `serve::run_with` after migrations; stop on the shutdown token (a run in progress finishes first).

| Job | Every | Does |
|---|---|---|
| `sweeper` | 60 s | `DELETE … WHERE expires_at < now()` on `login_transactions`, `authorization_codes`, `sessions`, `refresh_tokens`, `opaque_access_tokens`, `rate_limit_buckets` (readers already ignore expired rows; this bounds growth), and `audit_events` older than their tenant's `audit_retention_days` |
| `rotation` | 5 min | Per (tenant, alg), each tenant in its own transaction (one failing tenant doesn't block the others) while the run's lock transaction holds the leader lock: `KEY_PREPUBLISH_HOURS` before the active key is `KEY_ROTATION_DAYS` old, publish a `next` key (in JWKS, not signing); once it has been published that long, retire the active key (`expires_at` = now + the tenant's longest access-token TTL, min 1 h, + 1 h) and activate the next one — retire first, in one transaction, because the partial unique indexes allow one active key per (tenant, alg) per statement. Runs on an explicit `now` (tests move the clock) |

## HTTP surface (current)

Tenant `{t}` lives only at `{t}.{PUBLIC_URL host}[:port]`; its issuer is that origin.
`tenancy::resolve_host` gates every route but the probes. The request authority is the
absolute-form target / HTTP/2 `:authority` if present, else `Host` (RFC 9112 §3.2.2); more
than one `Host` header → 400. It must match exactly: ASCII case-insensitive, the scheme's
default port (`:443` for https, `:80` for http) spelled out counts as none; another port, trailing dot, nested label or
IP literal → 404. `X-Forwarded-Host` / `Forwarded` are never trusted. Unknown or disabled
tenants are 404 everywhere, and so are enabled tenants whose slug today's rules reject
(startup refuses to run with any — rename or disable them). The apex serves only
`GET /` → 302 `{scheme}://system.{host}/admin`. Paths below are per tenant host.

Trust model: issuer, redirect URLs and the CSRF origin all derive from `PUBLIC_URL` plus
the tenant's slug in the DB, never from request text, so a client choosing its `Host`
only reaches a tenant it could visit anyway. Hence no shared cache or CDN in front may
key responses on the path without the host, and the ingress must forward `Host`
unchanged (ingress-nginx: leave `use-forwarded-headers` off unless another trusted
proxy sits in front; the server ignores the forwarded host either way).

| Route | Listener | Module |
|---|---|---|
| `GET /healthz` — process alive, no DB dependency (any host) | app | `health` |
| `GET /readyz` — migrations done + DB ping, else 503 (any host) | app | `health` |
| `GET /` on the apex → 302 to the system admin portal | app | `tenancy` |
| `GET /.well-known/openid-configuration` | app | `oidc::discovery` |
| `GET /discovery/keys` — JWKS (next + active + unexpired retired), `max-age=300` | app | `oidc::discovery` |
| `GET /oauth2/authorize` | app | `oidc::authorize` |
| `POST /oauth2/token` | app | `oidc::token`, `oidc::refresh_grant` |
| `GET\|POST /oauth2/userinfo` | app | `oidc::userinfo` |
| `POST /oauth2/introspect` (RFC 7662) | app | `oidc::introspect` |
| `POST /oauth2/revoke` (RFC 7009) | app | `oidc::revoke` |
| `GET /oauth2/logout` (RP-initiated), `POST` (confirmation page, CSRF-checked) | app | `oidc::logout` |
| `GET /api/authn/tx/{id}`, `POST …/{password,totp,recovery,change-password,consent}` — login JSON API, contract in [api/authn.md](api/authn.md) | app | `authn` |
| `/api/v1/{settings,users,groups,directory-roles,applications,role-assignments,consents,audit-events}[/…]`, `/api/v1/me[/…]`, and on the system host only `/api/v1/tenants[/{slug}]` (system Global Admins) — management REST API, bearer tokens for the host tenant's `management-api`; contract in [api/management.md](api/management.md) | app | `api` |
| `/{login,logout,myaccount,admin}[/…]` → `index.html` | app | `spa` |
| any other path → static file from `WEB_DIST_DIR`, else 404 | app | `spa` |
| `GET /metrics` — Prometheus text format | metrics | `metrics` |

A missing SPA build only logs a warning; SPA routes then return 404.

## Server modules (`crates/server/src/`)

Implemented:

| Module | Responsibility |
|---|---|
| `config` | Env parsing + validation (`env.rs`, `Config::from_lookup` for tests); `PublicUrl` (`public_url.rs`: origin-only `PUBLIC_URL`, `tenant_origin`, `host_kind`); redacting `Debug` |
| `error` | `AppError` → JSON `{error, error_description}`; 5xx causes logged, never leaked |
| `app` | `AppState { db, migrated }` and router assembly (trace + metrics layers) |
| `db` | Pool connect; `migrate()` in one transaction holding `pg_advisory_xact_lock`; `migrate_and_reconcile()` (startup) adds `builtin_apps::reconcile_all` to it |
| `health` | `/healthz`, `/readyz` |
| `metrics` | Global Prometheus recorder, `/metrics` router, `http_requests_total` + `http_request_duration_seconds`. Labels are bounded: `path` = route template (fallback → `unmatched`), `method` = standard verb or `other` |
| `spa` | `ServeDir` + history fallback for the three SPA areas |
| `serve` | `run` (process-global setup: recorder, binds, signals) → `run_with` (serve, then migrate, then ready; tested in `tests/serve.rs`), tracing init, graceful shutdown |
| `keys` | Per-tenant RS256 (2048-bit) / ES256 key generation, `wrap` (AES-256-GCM seal/open, AAD = tenant id ‖ kid), public JWK with RFC 7638 thumbprint as `kid`, `active_signing_key`, `jwks` (next + active + retired-until-`expires_at`). Rotation job lands in step 3. See [Cryptography](#cryptography) |
| `directory` | `create_tenant` (DNS-label slug rules in `slug`, keys + built-in apps in one transaction; `builtin_apps::reconcile_all`), `create_user`, `find_user_by_email`, `set_password` (argon2id in `password`), `assign_directory_role`; typed `DirectoryError` |
| `bootstrap` | `oauth bootstrap` logic + report rendering |
| `headers` | `content_type_is`; app-wide `X-Frame-Options: DENY`, `CSP: frame-ancestors 'none'`, `Referrer-Policy: no-referrer` |
| `tenancy` | `resolve_host` middleware (host → active tenant, apex redirect, else 404) and the `Tenant` extractor reading its result |
| `secret` | Random bearer secrets (256-bit, base64url), random UUIDv4 handles, SHA-256 storage hash, constant-time compare |
| `oidc` | Protocol endpoints; `params` (duplicate-rejecting form/query parsing, `AuthRequest`), `pkce`, `redirect` (matching + building), `scope` (parsing, resource resolution), `client_auth`, `error` (`OAuthError`, RFC 6749 JSON + `WWW-Authenticate`, `no-store`) |
| `authn` | Login JSON API + CSRF guard (`AuthnError`, `JsonBody`), `cookie` (session + tx-binding cookies), `ctx`, `tx` (login transactions + browser binding + view), `password`, `mfa` (TOTP / recovery), `complete` (next step, consent, session + code), `session` (cookie), `totp` (RFC 6238 via AWS-LC HMAC, sealed secret, replay-protected step), `recovery`, `rate_limit`, `ip` |
| `consent` | Pure evaluation (granted / needs user / needs admin) + grant lookup / merge-upsert |
| `tokens` | Issuance (`issue_delegated`, `issue_app_only`), `inspect` (access-token resolution incl. user-disabled check), `claims` (pure builders), `jwt` (sign with active key, verify against published keys + `typ`), `opaque`, `refresh` (family state machine, rotation, revocation), `code`, `principal` (groups, roles) |
| `jobs` | `sweeper` (incl. audit retention), `rotation`, leader lock helper |
| `api` | Management REST API: `auth` (`Caller` / `SystemAdmin` bearer extractors), `guard` (administrator protection, last-GlobalAdmin lock), `page` (UUIDv7 keyset pagination), `validate` (client ids, redirect / identifier URIs, scope values), `app_rules` (app lookup + row lock, built-in protection, credential protection of privileged apps, lifetime and per-app caps), `extract` (JSON-error extractors), one module per resource (`tenants`, `users`, `user_actions`, `groups`, `directory_roles`, `applications`, `apps_secrets`, `apps_scopes`, `apps_roles`, `apps_permissions`, `role_assignments`, `consents`, `audit_events`, `me`, `me_mfa`) |
| `authz` | Pure permission matrix (directory roles, `Directory.Read.All` / `ReadWrite.All`) and administrator protection |
| `audit` | Closed `EventType` set, `record` (on the mutation's transaction), `token_replay`, retention `sweep` |

## Cryptography

All of the application's own cryptography uses AWS-LC (`aws-lc-rs`), except
password hashing. (`ring` is still linked transitively through sqlx's rustls
for the database TLS connection; that is the TLS stack's choice, not ours.)

| Use | Primitive |
|---|---|
| Token signing keys | RSA-2048 (RS256) and P-256 (ES256) generated by AWS-LC, stored as PKCS#8 DER; JWS via `jsonwebtoken` with its `aws_lc_rs` backend (RSA keys reach it as PKCS#8 PEM — AWS-LC can't export the PKCS#1 DER its raw-DER path expects) |
| Secrets at rest (signing keys, TOTP) | AES-256-GCM under `OAUTH_MASTER_KEY`, random 96-bit nonce, sealed as `nonce ‖ ciphertext ‖ tag`, AAD binding the blob to its row (signing keys: tenant id ‖ kid; TOTP: `"totp"` ‖ tenant id ‖ user id) |
| Bearer values (session cookie, codes, refresh / opaque access tokens, client secrets, recovery codes) | 256 random bits from AWS-LC; stored as SHA-256 only, looked up by hash (secrets compared in constant time) |
| TOTP | HMAC-SHA-1 (AWS-LC), 6 digits, 30 s, ±1 step, last used step stored (no replay) |
| PKCE | S256 only, required for every client |
| `kid` | RFC 7638 JWK thumbprint (SHA-256) |
| Passwords | argon2id (`argon2` crate), OWASP params m = 19 MiB, t = 2, p = 1; salt and one-time passwords from AWS-LC's RNG |

The `rsa` crate (RUSTSEC-2023-0071, Marvin timing attack) is deliberately
absent from the dependency graph. Building `aws-lc-sys` needs only a C
compiler.

## Crates

- `crates/entity` — SeaORM entities, one module per table, closed value sets
  in `enums.rs`.
- `crates/migration` — `Migrator`, append-only raw-SQL migrations.

## Data model

Every table but `tenants` carries `tenant_id`; child rows reference parents
through `(tenant_id, id)` composite FKs, so the database rejects links across
tenants. PKs are app-generated UUIDv7, timestamps `timestamptz`, enumerations
`text` + `CHECK` (Postgres enum values can't be added and used in the single
migration transaction). Deleting a tenant cascades to everything it owns.

| Table | Notes |
|---|---|
| `tenants` | `slug` unique (`^[a-z0-9][a-z0-9-]{1,62}$`, reserved list in `directory::slug`), `is_system` (at most one), `disabled`, `audit_retention_days` |
| `users` | `user_type` member\|guest, `email` unique per tenant on `lower(email)` (casing kept), `password_hash` (argon2id PHC, nullable), `must_change_password`, `disabled` |
| `user_totp` · `user_recovery_codes` | sealed TOTP secret + `confirmed_at`; SHA-256 code hashes + `used_at` |
| `groups` · `group_members` | static groups; members are users |
| `directory_role_assignments` | (user, role) unique; role GlobalAdmin\|ApplicationAdmin\|UserAdmin |
| `applications` | `client_id` unique per tenant, `client_type` confidential\|public, `builtin`, `redirect_uris[]`, `post_logout_redirect_uris[]`, `identifier_uri` (unique per tenant), `access_token_format` jwt\|opaque, `signing_alg` RS256\|ES256, access TTL 300–86400 s, refresh TTL |
| `client_secrets` | SHA-256 hash, display `hint`, optional `expires_at`; many per app for rotation |
| `app_scopes` · `app_roles` | delegated scopes (`admin_consent_required`) and app roles (`allowed_member_types` ⊆ {user, application}); `value` unique per app |
| `app_required_permissions` | client app → resource app, exactly one of `scope_id` / `app_role_id` (FK’d through the resource app) |
| `app_role_assignments` | role of a resource app → exactly one principal column (`user_id` / `group_id` / `client_application_id`) so deleting the principal cascades |
| `consent_grants` | (client, resource, user) unique; `user_id` NULL = tenant-wide admin consent; `scopes[]` |
| `signing_keys` | `kid` (JWK thumbprint) unique, `alg`, `status` next\|active\|retired (≤ 1 active and ≤ 1 next per tenant+alg), sealed private key (PKCS#8 DER, both algs), `public_jwk`, `activated_at` / `retired_at` / `expires_at` |
| `sessions` | `token_hash` (cookie), `amr[]`, `auth_time`, ip, user agent, `expires_at` (`SESSION_TTL_HOURS`); `id` is the `sid` claim |
| `login_transactions` | random UUIDv4 `id` (the `tx` handle), `binding_hash` (SHA-256 of the browser's tx-binding cookie), client app, `params` jsonb (validated `AuthRequest`), `stage` password\|mfa\|change_password\|consent, user / amr / auth_time once known, `session_id` when an existing session only needs consent; 15 min |
| `authorization_codes` | `code_hash`, client, user, session, redirect URI, scopes (OIDC + bare resource values), resource app, nonce, S256 challenge, amr, auth_time; 60 s, `consumed_at` (single use) |
| `refresh_tokens` | `token_hash`, `family_id`, client, user, session, originating code, scopes, resource, amr, auth_time, `expires_at` (fixed per family), `rotated_at`, `revoked_at` |
| `opaque_access_tokens` | `token_hash`, client, resource, user, originating code / family, `claims` jsonb, `expires_at`, `revoked_at` |
| `rate_limit_buckets` | (tenant, SHA-256 of key, window start) → count, `expires_at` |
| `audit_events` | `at`, `actor_type` user\|application\|system + `actor_id`, `event_type` (closed Rust enum `audit::EventType`, DB only checks the dotted shape so retired types stay valid history), `target_type` + `target_id`, `outcome` success\|failure, `ip`, `details` jsonb (never secrets). No FKs besides the tenant: events outlive what they mention. Indexed `(tenant_id, id DESC)` for newest-first listing, `(tenant_id, at)` for retention |

`user_totp.last_used_step` (added by the OIDC migration) prevents TOTP replay.
`applications_api_uri_is_own_client_id` (CHECK) lets an app use an
`identifier_uri` of the form `api://X` only when X is its own `client_id`, so
`api://X` always names one app (identifier URI first, then client id).
`session_id` / `authorization_code_id` / `family_id` are plain columns, not
FKs: sessions and codes are swept while the tokens they produced live on.

## Protocol

### Authorization request (`/oauth2/authorize`)

- `response_type=code` only, `response_mode=query` only; PKCE
  `code_challenge_method=S256` mandatory for every client; `request` /
  `request_uri` → `request_not_supported`.
- `redirect_uri` is required and must equal a registered URI exactly, except
  RFC 8252 loopback: a URI registered as `http://127.0.0.1/…` or
  `http://[::1]/…` (no port) matches any port. Until `client_id` and
  `redirect_uri` are validated, errors are 400 JSON, never redirects; after
  that, errors redirect with `error`, `error_description`, `state` and `iss`
  (RFC 9207, also on success).
- Scopes: `openid profile email offline_access` plus scopes of at most one
  resource app, `{identifier_uri}/{value}` or `api://{client_id}/{value}`;
  `{resource}/.default` = the client's registered required delegated
  permissions on it. At least one scope is required.
- `prompt=none|login|consent` (`none` alone), `max_age`. With a valid session
  (and no `prompt=login` / `max_age` violation) and consent satisfied, the
  code is issued immediately; otherwise a login transaction is created.
  `prompt=none` → `login_required` / `consent_required` instead.

### Consent

A delegated scope is covered by a user grant or a tenant-wide admin grant
(`consent_grants.user_id IS NULL`) for (client, resource). Missing scopes
with `admin_consent_required` → `access_denied` (interactive) /
`consent_required` (`prompt=none`), description "admin approval required for:
…" — users are never offered them. Other missing scopes go to the consent
step; approval merges them into the user's grant. `prompt=consent` asks again
for all user-consentable scopes. Built-in clients skip consent. OIDC scopes
need no consent (grants are keyed by a resource app).

### Token endpoint

- Client auth: `client_secret_basic` or `client_secret_post` for confidential
  clients (unexpired secrets, SHA-256 compared in constant time), `client_id`
  alone for public clients (a public client sending a secret is rejected);
  more than one method → `invalid_request`.
- `authorization_code`: code must belong to the client, be unexpired and
  unconsumed, `redirect_uri` must match, PKCE verified — all **before** the
  atomic consume, so nobody without the verifier can burn a code. Consume
  and token issuance share one DB transaction: a concurrent redemption waits
  on the code's row lock, then finds it consumed. A consumed code presented
  again revokes the refresh-token families and opaque access tokens it
  produced (RFC 6749 §4.1.2). Replay detection works while the code row
  exists, i.e. until the sweeper deletes it (≤ 60 s after its 60 s expiry);
  later replays just get `invalid_grant`.
- `refresh_token`: only for grants that included `offline_access` (public
  clients too — rotation protects them). Every use rotates; the new token
  inherits the family's absolute `expires_at` (the client's
  `refresh_token_ttl_secs` from the first issue). Presenting a rotated token
  revokes the whole family. `scope` may narrow the access token (never
  widen); the new refresh token keeps the original scopes and resource.
  Scope / user checks happen before rotation, so a rejected request doesn't
  burn it. Rotation and issuance share one DB transaction, so of two
  concurrent redemptions the loser sees the token rotated and revokes the
  family including the winner's new token. A rotation refuses (→ reuse
  path) when any token of its family is revoked, and family revocation
  repeats its UPDATE until nothing changes (the first pass waits on the
  lock of a rotation in flight; the next sees its new token), so a
  revocation racing a rotation (replay, RFC 7009 revoke, code replay)
  never leaves a live token. Introspection reports a refresh token
  inactive if anything in its family is revoked.
- `client_credentials`: confidential clients only; `scope` must be exactly
  `{resource}/.default`; `roles` = app roles of the resource assigned to the
  client app (only roles allowing `application` members; delegated tokens
  only get roles allowing `user`); no refresh / ID token. App-only tokens
  carry no `scp`, so resources must authorize them by `roles`.
- Responses `Cache-Control: no-store`; errors RFC 6749 §5.2 JSON (401 +
  `WWW-Authenticate: Basic` for `invalid_client` after Basic auth).

### Tokens

| Token | Format / signing | Claims |
|---|---|---|
| Access (delegated) | The **resource** app's `access_token_format` (JWT RFC 9068, header `typ: at+jwt`, or opaque) and `signing_alg`, TTL `access_token_ttl_secs` | `iss sub aud exp iat nbf jti client_id azp tid oid sid amr auth_time scp roles groups ver idtyp=user`; `aud` = resource `identifier_uri` or `api://{client_id}`; `scp` = resource scope values; `roles` = user's and user's groups' app roles of the resource; `groups` = group ids, more than 200 → omitted and `hasgroups: true` |
| Access (OIDC scopes only) | JWT RS256, 1 h | as above with `aud = {issuer}/oauth2/userinfo`, `scp` = the OIDC scopes — the only tokens userinfo accepts |
| Access (app-only) | resource settings | `sub = oid =` client app id, `idtyp=app`, `roles`, no `scp` |
| ID token | JWT signed with the **client** app's `signing_alg`, `typ: JWT`, 1 h | `aud = client_id`, `azp`, `nonce`, `auth_time`, `amr`, `sid`, `oid`, `tid`, `at_hash`, `ver`, plus `name preferred_username` (profile) and `email email_verified` (email) |
| Refresh | opaque, rotating | — |

`amr`: `["pwd"]`, or `["pwd","otp","mfa"]` after a TOTP or recovery code.
Opaque access tokens store the same claim set as `claims` jsonb. JWT
verification (userinfo, introspection, `id_token_hint`) accepts only keys the
tenant still publishes and checks `typ`, so ID tokens can't pose as access
tokens.

### Userinfo, introspection, revocation, logout

- **userinfo** (`Authorization: Bearer` only): token must be valid, `aud` =
  the userinfo audience and `scp` ∋ `openid`; returns `sub` + profile/email
  claims per granted scope. Resource tokens are refused (Entra behaviour:
  userinfo needs a token for the userinfo audience).
- **introspect**: confidential clients only. Refresh tokens are reported
  active only to their client (scope qualified as in token responses);
  access tokens only to their client (`client_id`) or their resource (the
  caller's app id = the token's resource app id). Tokens of a disabled user
  are inactive. Anyone else gets `{"active": false}` — the same as an
  invalid token.
- **revoke**: any authenticated client for its own tokens. Refresh token →
  whole family; opaque access token → revoked; JWTs can't be recalled. Always
  200 for unknown / foreign tokens.
- **logout** (`GET`): with a valid `id_token_hint` (signature + issuer
  verified, expiry ignored) whose `sub` is the session's user, the session
  ends (row deleted, cookie cleared) and the browser goes to
  `post_logout_redirect_uri` (+ `state`) if the hint's client registered it
  (unregistered → 400, nothing ended), else to the SPA page
  `/logout?signed_out=1` (a navigation never ends on raw JSON).
  Without a valid hint, or with another user's, nothing ends: 302 to the SPA
  confirmation page `/logout`, which signs out via `POST /oauth2/logout`
  (JSON + `Origin`, see [api/authn.md](api/authn.md)) —
  a cross-site `<img>` can't log anyone out. Refresh tokens survive logout
  (offline access is independent of the browser session).

### Sessions & CSRF

Session cookie `__Host-oauth_sid` (`oauth_sid` with `COOKIE_SECURE=false`),
host-only so each tenant host has its own; session lookup is also filtered
by the host's tenant. `Path=/`, `HttpOnly`, `Secure`, `SameSite=Lax` (sent on
the RP's top-level GET to `/authorize`, not on cross-site POSTs); `__Host-`
stops sibling tenant hosts from planting cookies. `/authorize` also sets
`__Host-oauth_tx` (per host, refreshed per request, never cleared so
parallel tabs work), whose hash each login transaction stores: the
login API serves a transaction only to the browser that started it (no
cross-browser completion, no login CSRF / session fixation through a planted
`tx`). The login API and `POST /oauth2/logout` require `Content-Type:
application/json` and `Origin` = the tenant's own origin on every POST
(another tenant's pages are cross-origin, hence rejected). A new
sign-in deletes the browser's previous session; setting a password deletes
all the user's sessions and revokes their refresh / opaque tokens. Client IP
(rate limits, session record) = socket peer, or with `TRUSTED_PROXY_HEADER`
the right-most entry of that header (one trusted proxy hop assumed); IPv6 is
bucketed per /64. Request logs record method + route template only — never
the query string (codes, hints, transaction ids).

### Metrics

`oauth_logins_total{outcome}` (success, invalid_credentials, mfa_failed,
disabled, rate_limited), `oauth_tokens_issued_total{grant,format}`,
`oauth_token_errors_total{error}` — label values are compile-time constants.

### Built-ins per tenant

`create_tenant` (and bootstrap for `system`) provisions, atomically with the
tenant row: one active RS256 and one active ES256 key; `management-api`
(confidential resource, `identifier_uri = api://management-api`, delegated
scope `Directory.AccessAsUser` [admin consent], app roles `Directory.Read.All`
and `Directory.ReadWrite.All` for applications); `admin-portal` and
`my-account` (public SPA clients, redirect `{origin}/admin/callback` /
`{origin}/myaccount/callback`, post-logout to the area root, 24 h refresh TTL),
each requiring the management-api scope and pre-consented by a tenant-wide
admin `consent_grant`. The SPA URIs derive from `PUBLIC_URL`, so
`builtin_apps::reconcile_all` rewrites them for every tenant at each startup
(idempotent, inside the migration transaction, before `/readyz` turns ready).

## Management API

`/api/v1` — contract and permission matrix in
[api/management.md](api/management.md). Bearer tokens only (no cookies,
no CSRF surface): an access token of the host's tenant (JWT verified
against its published keys, or an active opaque token), `tid` = that
tenant, audience = the tenant's built-in `management-api`. Delegated tokens
need `scp ∋ Directory.AccessAsUser` and a still-existing session (`sid`),
and act through the user's directory roles (any role reads the directory;
GlobalAdmin writes everything, UserAdmin users / groups, ApplicationAdmin
apps / grants); app-only tokens act through their CURRENT
`Directory.Read.All` / `Directory.ReadWrite.All` assignments (looked up
per call, not taken from the token) and never touch directory roles or
tenants; a tenant's GlobalAdmin edits its own `settings`. `/api/v1/tenants` exists only on
the system host and is for GlobalAdmins of the `system` tenant. Administrators can only be modified by GlobalAdmins;
the last enabled GlobalAdmin can't be removed (per-tenant advisory lock
serializes the check, and role checks lock the target user row); built-in
apps are GlobalAdmin-only and read-mostly; management-API grants, and the
credentials / redirect URIs of apps holding them, need a GlobalAdmin.
Refresh-token lifetimes are capped (90 days; public clients 7 days). Objects of other tenants are 404, never 403.

Every mutation writes its `audit_events` row in the same transaction; the
login API records sign-ins (success with the new session, failures with a
reason code; rate-limited attempts are not logged) and forced password
changes; the token endpoint records refresh-token reuse and code replay.
Withdrawing a consent grant revokes the client's refresh families and
opaque access tokens for the resource (one user, or everyone for an admin
grant); deleting a scope revokes the families holding it, and refresh
never re-mints a scope the resource no longer exposes.

## Frontend (`web/`)

See [frontend.md](frontend.md): one Vue 3 SPA (`/login`, `/logout`, `/myaccount`,
`/admin`) served same-origin on every tenant host.

## Deployment

Multi-stage `Dockerfile` (node 22 → rust 1.99.0 → debian bookworm-slim, uid
10001). `deploy/k8s/deploy.yml`: ConfigMap, Deployment (2 replicas, liveness
`/healthz`, readiness `/readyz`, 5 s preStop sleep, no service-account token),
Service (http 8080, metrics 9090), PodDisruptionBudget (`minAvailable: 1`),
Ingress for the apex + `*.` wildcard host (TLS Secret `oauth-wildcard-tls`, a
cert-manager DNS-01 wildcard certificate; the controller must keep `Host`, see the
trust model under [HTTP surface](#http-surface-current)).
Secrets come from a hand-made Secret `oauth-secrets`. CI builds the image on
every PR (no push).
