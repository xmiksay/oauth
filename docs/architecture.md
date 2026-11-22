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
- `oauth telegram set-webhook` — registers `{PUBLIC_URL}/telegram/webhook` with the bot.
- `oauth bootstrap --admin-email … [--display-name …] [--reset-password]` —
  runs migrations, then (in one transaction holding a dedicated advisory lock,
  so concurrent runs serialize) applies the system-slug rule below, creates
  the system tenant (slug `SYSTEM_TENANT_SLUG`, default `system`) if missing and the
  admin if missing, ensures the admin holds `GlobalAdmin`, and prints a
  one-time password (`must_change_password = true`) to stdout. An existing
  admin's password is only replaced with `--reset-password`. Exit 0 either way.

Migrations: all pending ones run in a single transaction that first takes
`pg_advisory_xact_lock(MIGRATION_LOCK_KEY)` (replicas serialize; released exactly on
commit/rollback), so they must be transaction-safe (no `CREATE INDEX CONCURRENTLY`).
`serve` then, in that transaction, reconciles the system tenant's slug with `SYSTEM_TENANT_SLUG`
(`directory::reconcile_system_slug`: refuse a mismatch, or rename + audit with
`SYSTEM_TENANT_RENAME=1`, [deploy.md](deploy.md#system-tenant-slug)) before the slug and URI checks.

State lives only in PostgreSQL (sessions, codes, login transactions, rate
limits). Multiple replicas are safe: migrations serialize on the advisory lock,
background jobs run each tick inside a transaction holding
`pg_try_advisory_xact_lock(job key)` — one replica works, the others skip.

### Background jobs (`jobs`)

Spawned by `serve::run_with` after migrations: `sweeper`, `rotation`, `secret_expiry`, `outbox` — schedules and behaviour in [jobs.md](jobs.md).

## HTTP surface

Host routing, trust model and the route table: [http.md](http.md).

## Server modules (`crates/server/src/`)

Implemented:

| Module | Responsibility |
|---|---|
| `config` | Env parsing + validation (`env.rs`, `Config::from_lookup` for tests); `PublicUrl` (`public_url.rs`: origin-only `PUBLIC_URL`, `tenant_origin`, `host_kind`); `SmtpConfig` (`smtp.rs`: optional `SMTP_URL` + `SMTP_FROM`, both or neither, URL redacted); `TelegramConfig` (`telegram.rs`: bot token / username / webhook secret all or none, API URL https or loopback); redacting `Debug` |
| `error` | `AppError` → JSON `{error, error_description}`; 5xx causes logged, never leaked |
| `app` | `AppState { db, config, migrated, tasks, detached, telegram, upstream }` (`telegram`: the Bot API client; `upstream`: the federation client + discovery / JWKS caches; `tasks`: `TaskTracker` of work handlers leave running after answering, awaited at shutdown; `detached`: `Semaphore` capping it at 64 in flight) and router assembly (trace + metrics layers) |
| `db` | Pool connect; `migrate()` in one transaction holding `pg_advisory_xact_lock`; `migrate_and_reconcile()` (startup) adds `builtin_apps::reconcile_all` to it |
| `health` | `/healthz`, `/readyz` |
| `metrics` | Global Prometheus recorder, `/metrics` router, `http_requests_total` + `http_request_duration_seconds`. Labels are bounded: `path` = route template (fallback → `unmatched`), `method` = standard verb or `other` |
| `spa` | `ServeDir` + history fallback for the three SPA areas |
| `serve` | `run` (process-global setup: recorder, binds, signals) → `run_with` (serve, then migrate, then ready; tested in `tests/serve.rs`), tracing init, graceful shutdown |
| `keys` | Per-tenant RS256 (2048-bit) / ES256 key generation, `wrap` (AES-256-GCM seal/open, AAD = tenant id ‖ kid), public JWK with RFC 7638 thumbprint as `kid`, `active_signing_key`, `jwks` (next + active + retired-until-`expires_at`). Rotation job lands in step 3. See [Cryptography](#cryptography) |
| `directory` | `create_tenant` (DNS-label slug rules in `slug`, keys + built-in apps in one transaction; `builtin_apps::reconcile_all`), `ensure_apex_tenant` (startup: `APEX_TENANT` exists, is enabled and isn't the system tenant), `system_tenant` (`reconcile_system_slug`, at startup and bootstrap: refuses a stored system-tenant slug other than `SYSTEM_TENANT_SLUG`, or renames it with `SYSTEM_TENANT_RENAME=1` and retires the old slug), `retired_slugs` (`ensure_slug_not_retired`, `servable_tenant`), `create_user`, `find_user_by_email`, `set_password` (argon2id in `password`), `assign_directory_role`; typed `DirectoryError` |
| `bootstrap` | `oauth bootstrap` logic + report rendering |
| `headers` | `content_type_is`; app-wide `X-Frame-Options: DENY`, `CSP: frame-ancestors 'none'`, `Referrer-Policy: no-referrer` |
| `tenancy` | `resolve_host` middleware (host → active tenant, `APEX_TENANT` on the apex or the apex redirect, else 404) and the `Tenant` extractor reading its result |
| `secret` | Random bearer secrets (256-bit, base64url), random UUIDv4 handles, SHA-256 storage hash, constant-time compare |
| `cors` | CORS on discovery / JWKS / userinfo / token / revoke only: `validate_origin`, `origin_of` (a redirect URI's origin), `effective_origins` (explicit ∪ a public client's redirect-URI origins), `tenant_allows`; `http` (preflight handlers, `tenant_wide` middleware, `for_client` for token / revoke) — see [CORS](#cors) |
| `oidc` | Protocol endpoints; `params` (duplicate-rejecting form/query parsing, `AuthRequest`), `pkce`, `redirect` (matching + building), `scope` (parsing, resource resolution, `resolve_request` shared by authorize and device authorization), `mrrt` (refresh token redeemed for another consented resource), `assignment` (assignment-required checks), `client_auth`, `error` (`OAuthError`, RFC 6749 JSON + `WWW-Authenticate`, `no-store`), `device_authorization` / `device_grant` (RFC 8628); sibling `backchannel`: Back-Channel Logout (`record_client` on issuance, `queue` before sessions are deleted, `token`, `deliver::Notifier` outbox `Courier`) — [backchannel_logout.md](backchannel_logout.md) |
| `device_flow` | Device authorization state: `user_code` (alphabet, normalising, hashing), issue (code pair, user code unique per tenant), lookup by user code, the decision (CAS on `pending`, records the approving session), poll bookkeeping (`slow_down`), the approving session's lock + liveness, denying unredeemed approvals on revocation, consumption |
| `mail` | `Mailer` trait (`Email`, `MailError` transient/permanent) + `SmtpMailer` (lettre, rustls on AWS-LC, webpki roots, 15 s command timeout); `templates` (plain-text link messages and security notices); `outbox` (`enqueue` on the caller's transaction, body sealed, backoff schedule); `tokens` (email link tokens: issue voids the user's older ones of that purpose, atomic single-use `consume` scoped to the tenant); `links::send` (token + message + outbox row) |
| `notify` | Security notices (`notify::event`, `email_changed` to the old address) honouring `notification_prefs` (no row = on); email only to a verified address, Telegram to a linked chat |
| `http` | Shared outbound client recipe (rustls on AWS-LC, webpki roots, no redirects, no proxy, timeouts) and capped body reads |
| `federation` | Upstream OIDC / OAuth2 (relying-party side): `discovery` (discovery + JWKS caches), `exchange` (code exchange), `id_token` (signature + claims), `flow` (begin / finish of a round trip), `state` (single-use `federation_states`), `identities` (links, last-method rule), `group_map` (claim value → group mappings, applied per sign-in), `idps`, `policy`, `profile` (bounding upstream claims), `resolve` (public-address-only DNS), `urls`, `kinds` (per-preset claim checks: Google `hd`, Entra `tid` + `{tenantid}` issuer template + allowed tenants, `xms_edov` / `trust_upstream_email` as verified email), `github` (OAuth2 adapter, no OIDC: `/user` + `/user/emails`, verified primary email, numeric id as subject) — [federation.md](federation.md) |
| `telegram` | Bot: `api` (reqwest `sendMessage` / `setWebhook`, token never logged; outbox `Courier`), `update` (pure update parsing), `links` (link codes, links), `otp` (sign-in codes), `webhook`, `set_webhook` (CLI) — [telegram.md](telegram.md) |
| `authn` | Login JSON API + CSRF guard (`AuthnError`, `JsonBody`), `passkey` (passkey sign-in), `invite_passkey` (invitation accepted with a passkey), `cookie` (session, tx-binding and device cookies), `device` (known devices + new sign-in notice), `telegram` (sending sign-in codes), `reset` (password-reset request / completion), `email` (verify / invite link redemption), `federation` / `federation_login` / `federation_link` / `federation_pending` (upstream sign-in, linking callbacks, stage `link`), `device_code` (user-code entry → transaction, device approve / deny), `ctx`, `tx` (login transactions + browser binding), `tx_view` (`GET /api/authn/tx/{id}`), `password`, `mfa` (TOTP / recovery / Telegram codes), `complete` (next step, consent, session + code), `complete_refuse` (completion refusals that close the transaction and deny a device request), `consent_eval` (consent state of a pending request), `session` (cookie), `totp` (RFC 6238 via AWS-LC HMAC, sealed secret, replay-protected step), `recovery`, `rate_limit`, `ip` |
| `consent` | Pure evaluation (granted / needs user / needs admin) + grant lookup / merge-upsert |
| `tokens` | Issuance (`issue_delegated`, `issue_app_only`), `inspect` (access-token resolution incl. user-disabled check), `claims` (pure builders), `jwt` (sign with active key, verify against published keys + `typ`), `opaque`, `refresh` (family state machine, rotation, revocation), `code`, `principal` (groups, roles) |
| `jobs` | `sweeper` (incl. audit retention), `rotation`, `secret_expiry` (expiring client-secret warnings), `outbox` (delivery per channel `Courier`: email, Telegram, back-channel logout), leader lock helper |
| `api` | Management REST API: `auth` (`Caller` / `SystemAdmin` bearer extractors), `guard` (administrator protection, last-GlobalAdmin lock), `page` (UUIDv7 keyset pagination), `validate` (client ids, redirect / identifier URIs, scope values), `secret_value` (length / entropy check of caller-supplied client secrets), `app_rules` (app lookup + row lock, built-in protection, credential protection of privileged apps, lifetime and per-app caps), `extract` (JSON-error extractors), one module per resource (`tenants`, `tenant_users` (system admin: another tenant's users, password / MFA reset), `users`, `user_actions`, `user_invite`, `user_identities`, `groups`, `directory_roles`, `applications`, `identity_providers` (+ `idp_body`, `idp_validate`, `idp_rules` (per-kind cross-field rules + defaults), `idp_group_mappings`), `apps_secrets`, `apps_scopes`, `apps_roles`, `apps_permissions`, `role_assignments`, `consents`, `audit_events`, `me`, `me_mfa`, `me_email`, `me_passkeys`, `me_telegram`, `me_identities`, `user_passkeys`), `reauth` (password-or-passkey re-authentication) |
| `webauthn` | Own WebAuthn verifier on AWS-LC + `ciborium`: `cbor`, `authdata`, `cose`, `client_data`, `register`, `assert` — see [passkeys.md](passkeys.md) |
| `passkey` | Passkey ceremonies over the DB: `challenge` (single-use, 5 min), `store` (credentials, user handle, last-method rule), `wire` (browser JSON, options) |
| `authz` | Pure permission matrix (directory roles, `Directory.Read.All` / `ReadWrite.All`) and administrator protection |
| `audit` | Closed `EventType` set, `record` (on the mutation's transaction), `token_replay`, retention `sweep` |

## Cryptography

All of the application's own cryptography uses AWS-LC (`aws-lc-rs`), except
password hashing. (`ring` is still linked transitively through sqlx's rustls
for the database TLS connection; that is the TLS stack's choice, not ours.)

| Use | Primitive |
|---|---|
| Token signing keys | RSA-2048 (RS256) and P-256 (ES256) generated by AWS-LC, stored as PKCS#8 DER; JWS via `jsonwebtoken` with its `aws_lc_rs` backend (RSA keys reach it as PKCS#8 PEM — AWS-LC can't export the PKCS#1 DER its raw-DER path expects) |
| Secrets at rest (signing keys, TOTP, outbox bodies, IdP client secrets, upstream PKCE verifiers) | AES-256-GCM under `OAUTH_MASTER_KEY`, random 96-bit nonce, sealed as `nonce ‖ ciphertext ‖ tag`, AAD binding the blob to its row (signing keys: tenant id ‖ kid; TOTP: `"totp"` ‖ tenant id ‖ user id; outbox: `"outbox"` ‖ tenant id ‖ message id; IdP: `"idp"` ‖ tenant id ‖ IdP id; PKCE: `"fedpkce"` ‖ tenant id ‖ state id) |
| Upstream ID tokens | RS256 / ES256 / EdDSA verified with AWS-LC via `jsonwebtoken`; the algorithm comes from the JWK, never the token — [federation.md](federation.md#security-model) |
| Bearer values (session and device cookies, codes, refresh / opaque access tokens, client secrets, recovery codes, email link tokens, upstream `state`) | 256 random bits from AWS-LC; stored as SHA-256 only, looked up by hash (secrets compared in constant time) |
| TOTP | HMAC-SHA-1 (AWS-LC), 6 digits, 30 s, ±1 step, last used step stored (no replay) |
| PKCE | S256 only, required for every client |
| `kid` | RFC 7638 JWK thumbprint (SHA-256) |
| Passkeys | WebAuthn assertions verified with AWS-LC (ES256 P-256, EdDSA Ed25519, RS256 ≥ 2048 bits); challenges stored as SHA-256 — [passkeys.md](passkeys.md) |
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
| `tenants` | `slug` unique (`^[a-z0-9][a-z0-9-]{1,62}$`, reserved list in `directory::slug`), `is_system` (at most one), `disabled`, `audit_retention_days`, `mfa_policy` optional\|required, `logout_revokes_refresh_tokens` (default true), `allow_non_expiring_secrets` (default false) |
| `retired_tenant_slugs` | PK `slug`, `tenant_id` (the system tenant), `retired_at`: slugs the system tenant was renamed away from, reserved against regular tenants for good (`directory::retired_slugs`; written only by `reconcile_system_slug`; a trigger enforces append-only and system-tenant-only; backfilled at creation from `tenant.rename` audit events) |
| `users` | `user_type` member\|guest, `email` unique per tenant on `lower(email)` (casing kept), `password_hash` (argon2id PHC, nullable), `must_change_password`, `disabled`, `first_device_at` (first sign-in device recorded), `webauthn_handle` (random 32-byte WebAuthn user handle) |
| `webauthn_credentials` · `webauthn_challenges` | passkeys (credential id unique per tenant, COSE key, counter, backup flags) and single-use 5-min ceremony challenges — [passkeys.md](passkeys.md) |
| `user_totp` · `user_recovery_codes` | sealed TOTP secret + `confirmed_at`; SHA-256 code hashes + `used_at` |
| `groups` · `group_members` | static groups; members are users; `display_name` unique per tenant case-insensitively (index on `(tenant_id, lower(display_name))`); a membership is `manual` (an admin added it) and/or kept by an IdP's group mappings (`idp_id`) — [federation.md](federation.md#group-mappings) |
| `directory_role_assignments` | (user, role) unique; role GlobalAdmin\|ApplicationAdmin\|UserAdmin |
| `applications` | `client_id` unique per tenant, `client_type` confidential\|public, `builtin`, `redirect_uris[]`, `post_logout_redirect_uris[]`, `web_origins[]` (explicit CORS origins, ≤ 32), `identifier_uri` (unique per tenant), `access_token_format` jwt\|opaque, `signing_alg` RS256\|ES256, `groups_claim_format` id\|name, `id_token_groups` none\|all\|assigned, `assignment_required`, access TTL 300–86400 s, refresh TTL, `device_code_enabled` (RFC 8628 opt-in), `mfa_policy` inherit\|required, `backchannel_logout_uri` (https; [backchannel_logout.md](backchannel_logout.md)), `backchannel_logout_session_required` |
| `client_secrets` | SHA-256 hash, display `hint`, optional `expires_at` (`NULL` only where the tenant's `allow_non_expiring_secrets` allowed it at creation), `expiry_notified_at` (expiry warning queued); generated or caller-supplied value; many per app for rotation |
| `app_scopes` · `app_roles` | delegated scopes (`admin_consent_required`) and app roles (`allowed_member_types` ⊆ {user, application}); `value` unique per app |
| `app_required_permissions` | client app → resource app, exactly one of `scope_id` / `app_role_id` (FK’d through the resource app) |
| `app_role_assignments` | role of a resource app → exactly one principal column (`user_id` / `group_id` / `client_application_id`) so deleting the principal cascades |
| `consent_grants` | (client, resource, user) unique; `user_id` NULL = tenant-wide admin consent; `scopes[]` |
| `signing_keys` | `kid` (JWK thumbprint) unique, `alg`, `status` next\|active\|retired (≤ 1 active and ≤ 1 next per tenant+alg), sealed private key (PKCS#8 DER, both algs), `public_jwk`, `activated_at` / `retired_at` / `expires_at` |
| `sessions` | `token_hash` (cookie), `amr[]`, `auth_time`, ip, user agent, `expires_at` (`SESSION_TTL_HOURS`); `id` is the `sid` claim. `session_clients` `(session_id, application_id)`: clients that obtained tokens in it (Back-Channel Logout recipients; cascades with the session and the app) |
| `login_transactions` | random UUIDv4 `id` (the `tx` handle), `binding_hash` (SHA-256 of the browser's tx-binding cookie), client app, `params` jsonb (validated `AuthRequest`), `stage` password\|link\|mfa\|mfa_enroll\|change_password\|consent, user / amr / auth_time once known (a step-up starts with the session's), `session_id` when an existing session only needs consent or is stepped up (`step_up`: completion requires it still live and upgrades it in place: same id, new amr / auth_time, rotated cookie) (a device sign-in names its `device_authorizations` row in `params.device`), `pending_identity` jsonb (stage `link`), `federated` jsonb (IdP + generation of an upstream sign-in); 15 min |
| `identity_providers` · `user_identities` · `federation_states` · `idp_group_mappings` | upstream providers, `kind` oidc\|google\|entra\|github (name unique per tenant, sealed secret, policy, MFA trust, email domains, `hosted_domain`, `allowed_tenants[]`, `trust_upstream_email`), linked (IdP, subject) per user (one per IdP), single-use 10-min round-trip state, upstream claim value → local group — [federation.md](federation.md#data) |
| `device_authorizations` | `device_code_hash` (unique), `user_code_hash` (unique per tenant), client, scopes (OIDC + bare resource values), resource app, `status` pending\|approved\|denied, `user_id` (who decided) + `amr` / `auth_time` of the approving sign-in, `approved_session_id` (FK `SET NULL`: redemption refuses once it ended), `interval_secs` (5, +5 per `slow_down`, ≤ 60), `last_polled_at`, `decided_at`, `consumed_at` (single redemption); 15 min |
| `authorization_codes` | `code_hash`, client, user, session, redirect URI, scopes (OIDC + bare resource values), resource app, nonce, S256 challenge, amr, auth_time; 60 s, `consumed_at` (single use) |
| `refresh_tokens` | `token_hash`, `family_id`, client, user, session, originating code, scopes, resource, amr, auth_time, `expires_at` (fixed per family), `rotated_at`, `revoked_at` |
| `opaque_access_tokens` | `token_hash`, client, resource, user, originating code / family, `claims` jsonb, `expires_at`, `revoked_at` |
| `rate_limit_buckets` | (tenant, SHA-256 of key, window start) → count, `expires_at` |
| `outbox` | `channel` email\|telegram\|backchannel, `recipient`, `kind` (shape-checked), `subject`, `body_enc` (sealed: bodies carry link tokens; NULL once sent or dead), `attempts`, `next_attempt_at`, `last_error` (error kind only), `sent_at`, `dead_at`, `expires_at` (= the link's lifetime, notices 24 h). Only the tenant FK |
| `email_tokens` | `token_hash` (unique), user, `email` (the address at issue time; redeeming requires it unchanged), `purpose` verify\|reset\|invite\|change (24 h / 30 min / 7 d / 24 h), `new_email` (change only, CHECK), `consumed_at` (single use) |
| `known_devices` | (tenant, user, SHA-256 of user id ‖ device cookie) unique, user agent, `first_seen` / `last_seen`, `expires_at` 1 y (refreshed per sign-in) |
| `telegram_links` · `telegram_link_codes` · `telegram_otps` | linked chat per user, single-use 10-min link codes, per-transaction 5-min sign-in codes — [telegram.md](telegram.md#data) |
| `notification_prefs` | PK (tenant, user, event ∈ password_changed, mfa_changed, email_changed, new_sign_in, token_reuse, identity_linked); `email`, `telegram` booleans; no row = both on |
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
- Scopes: `openid profile email offline_access groups` plus scopes of at most one
  resource app per request (one refresh token still spans resources, see
  the token endpoint), `{identifier_uri}/{value}` or `api://{client_id}/{value}`;
  `{resource}/.default` = the client's registered required delegated
  permissions on it. At least one scope is required. `groups` is known so
  clients that always request it (Headlamp, Grafana, ArgoCD) aren't refused,
  but releases nothing by itself: the client's `id_token_groups` alone
  decides whether ID tokens / userinfo carry groups. Like every OIDC scope it
  is kept in the grant and can be narrowed away, never added, on refresh;
  resource apps may not expose it. Unknown scopes stay `invalid_scope`.
- `prompt=none|login|consent` (`none` alone), `max_age`. With a valid session
  (and no `prompt=login` / `max_age` violation) and consent satisfied, the
  code is issued immediately; otherwise a login transaction is created.
  `prompt=none` → `login_required` / `consent_required` instead.

### Consent and assignment required

A delegated scope needs a user or tenant-wide admin grant for (client,
resource); `admin_consent_required` scopes are never offered to users. An app
with `assignment_required` serves only principals holding one of its roles,
checked before consent and on every token grant: [consent.md](consent.md).

### Token endpoint

- Client auth: `client_secret_basic` or `client_secret_post` for confidential
  clients (unexpired secrets, SHA-256 compared in constant time), `client_id`
  alone for public clients (a public client sending a secret is rejected);
  more than one method → `invalid_request`.
- `authorization_code`: code must belong to the client, be unexpired and
  unconsumed, `redirect_uri` must match, PKCE verified — all **before** the
  atomic consume, so nobody without the verifier can burn a code. Consume
  and token issuance share one DB transaction: a concurrent redemption waits
  on the code's row lock, then finds it consumed. The code's session must
  still exist: the transaction locks its user, then it (`backchannel::record_client`,
  `FOR KEY SHARE`, before the consume — lock order user → session → tokens) and refuses with `invalid_grant` once
  it has ended, so a logout either kills the unredeemed code or waits for the
  redemption and then revokes and announces its tokens. A consumed code presented
  again revokes the refresh-token families and opaque access tokens it
  produced (RFC 6749 §4.1.2). `backchannel::lock_user` re-reads the user
  under its lock: one disabled or deleted while the redemption waited on it
  gets `invalid_grant` (a `disabled` read before the lock is stale). Replay detection works while the code row
  exists, i.e. until the sweeper deletes it (≤ 60 s after its 60 s expiry);
  later replays just get `invalid_grant`.
- `refresh_token`: only for grants that included `offline_access`; every
  use rotates within one family (reuse revokes it), and a refresh may mint
  an access token for another resource (multi-resource refresh): rotation,
  races and MRRT in [refresh_tokens.md](refresh_tokens.md). The grant
  locks the user first and re-reads them under that lock: one disabled or
  deleted meanwhile gets `invalid_grant`.
- `client_credentials`: confidential clients only; `scope` must be exactly
  `{resource}/.default`; `roles` = app roles of the resource assigned to the
  client app (only roles allowing `application` members; delegated tokens
  only get roles allowing `user`); no refresh / ID token. App-only tokens
  carry no `scp`, so resources must authorize them by `roles`.
- `urn:ietf:params:oauth:grant-type:device_code` (RFC 8628): [device_code.md](device_code.md).
- Responses `Cache-Control: no-store`; errors RFC 6749 §5.2 JSON (401 +
  `WWW-Authenticate: Basic` for `invalid_client` after Basic auth).

### Tokens

| Token | Format / signing | Claims |
|---|---|---|
| Access (delegated) | The **resource** app's `access_token_format` (JWT RFC 9068, header `typ: at+jwt`, or opaque) and `signing_alg`, TTL `access_token_ttl_secs` | `iss sub aud exp iat nbf jti client_id azp tid oid sid amr acr auth_time scp roles groups ver idtyp=user` (`acr: "mfa"` only after a multi-factor sign-in); `aud` = resource `identifier_uri` or `api://{client_id}`; `scp` = resource scope values; `roles` = user's and user's groups' app roles of the resource; `groups` = group ids, or display names when the resource's `groups_claim_format` is `name` (read at issuance, so a rename shows on the next token); more than 200 → omitted and `hasgroups: true` (either format) |
| Access (OIDC scopes only) | JWT RS256, 1 h | as above (`groups` always ids) with `aud = {issuer}/oauth2/userinfo`, `scp` = the OIDC scopes — the only tokens userinfo accepts |
| Access (app-only) | resource settings | `sub = oid =` client app id, `idtyp=app`, `roles`, no `scp` |
| ID token | JWT signed with the **client** app's `signing_alg`, `typ: JWT`, 1 h | `aud = client_id`, `azp`, `nonce`, `auth_time`, `amr`, `acr` (`mfa`, multi-factor sign-ins only), `sid`, `oid`, `tid`, `at_hash`, `ver`, plus `name preferred_username` (profile) and `email email_verified` (email), and `groups` / `hasgroups` per the client's `id_token_groups` (`all` = every group, `assigned` = groups holding one of the client's user roles) in the client's `groups_claim_format`, overage rule as for access tokens |
| Refresh | opaque, rotating | — |

`amr` values per sign-in method: [authn.md](authn.md#login-transactions).
Opaque access tokens store the same claim set as `claims` jsonb. JWT
verification (userinfo, introspection, `id_token_hint`) accepts only keys the
tenant still publishes and checks `typ`, so ID tokens can't pose as access
tokens.
Discovery's `claims_supported` lists ID token / userinfo claims only (incl.
`groups` / `hasgroups`, which `id_token_groups` can add), so the
access-token-only `scp` and `roles` aren't in it. Consumers binding to group
names either validate access tokens for a resource app with
`groups_claim_format: name`, or (Kubernetes structured authentication fed the
ID token by Headlamp, Grafana) read the ID token of a client app with
`id_token_groups: all|assigned` and `groups_claim_format: name`.

### Userinfo, introspection, revocation, logout

- **userinfo** (`Authorization: Bearer` only): token must be valid, `aud` =
  the userinfo audience and `scp` ∋ `openid`; returns `sub` + profile/email
  claims per granted scope, plus `groups` / `hasgroups` per the token's
  client's `id_token_groups` (option and memberships read at call time).
  Resource tokens are refused (Entra behaviour:
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
  a cross-site `<img>` can't log anyone out. Back-Channel Logout and refresh
  revocation on logout: [backchannel_logout.md](backchannel_logout.md).

### CORS

Only discovery, JWKS, token, revoke and userinfo answer cross-origin; an
app's allowed origins are its `web_origins` plus (public clients) its
redirect URIs' origins: [cors.md](cors.md).

### Sessions & CSRF

Cookies, browser binding, CSRF and client IPs: [authn.md](authn.md#sessions--csrf).

### Metrics

`oauth_logins_total{outcome}` (success, invalid_credentials, mfa_failed,
disabled, rate_limited, upstream_failed), `oauth_tokens_issued_total{grant,format}`,
`oauth_token_errors_total{error}` — label values are compile-time constants.

### Built-ins per tenant

`create_tenant` (and bootstrap for the system tenant) provisions, atomically with the
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
the system host and is for GlobalAdmins of the system tenant (`is_system`; slug `SYSTEM_TENANT_SLUG`), who can also look up another tenant's users and reset their password / MFA there (`tenants/{slug}/users`, audited in both tenants' logs). Administrators can only be modified by GlobalAdmins;
the last enabled GlobalAdmin can't be removed (per-tenant advisory lock
serializes the check, and role checks lock the target user row); built-in
apps are GlobalAdmin-only and read-mostly; management-API grants, and the
credentials / redirect URIs of apps holding them, need a GlobalAdmin.
Refresh-token lifetimes are capped (90 days; public clients 7 days). Objects of other tenants are 404, never 403.

Every mutation writes its `audit_events` row in the same transaction; the
login API records sign-ins (success with the new session, failures with a
reason code; rate-limited attempts are not logged) and forced password
changes; the token endpoint records refresh-token reuse and code replay.
Withdrawing a consent grant or deleting a scope revokes the tokens built on
it: [refresh_tokens.md](refresh_tokens.md#revocation-by-directory-changes).

## Sign-in methods

Login flow, stages, `amr`, rate limits and the last-method rule in [authn.md](authn.md).
Email (optional) [email.md](email.md), passkeys [passkeys.md](passkeys.md), Telegram
(optional) [telegram.md](telegram.md), upstream identity providers [federation.md](federation.md).

## Frontend (`web/`)

See [frontend.md](frontend.md): one Vue 3 SPA (`/` portal, `/login`, `/logout`, `/myaccount`,
`/admin`) served same-origin on every tenant host.

## Deployment

Multi-stage `Dockerfile` (node 22 → rust 1.99.0 → debian bookworm-slim, uid
10001). The repository carries no deployment manifests (both environments'
Kubernetes objects live in the ansible repo; CI only updates the test
Deployment's image); the requirements any deployment must meet (apex + wildcard
host and TLS, `Host` passed unchanged, probes, metrics port, Secret vs config
env, one database, migrations on startup, replicas) are in
[deploy.md](deploy.md#deployment-requirements), and
[examples/k8s.yml](examples/k8s.yml) is a non-authoritative Kubernetes example.
CI builds the image on
every PR (no push), publishes it to GHCR from `main` and `v*` tags and rolls
`main` out to test.oauth.cz — see [deploy.md](deploy.md).
