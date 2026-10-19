# Roadmap

## M1a — core IdP (one branch / PR per step, gate green before push)

1. **`feat/m1a-scaffold`** — Cargo workspace, toolchain pins, Makefile, CI,
   compose, config, error type, health/metrics, migration runner + advisory
   lock, SPA serving, Vue skeleton, Dockerfile, k8s manifests, docs.
2. **`feat/m1a-directory`** (done) — tenants / users / groups / directory roles
   entities + migrations, `keys` module, `oauth bootstrap` CLI, built-in apps
   (`management-api`, `admin-portal`, `my-account`) on tenant creation.
3. **`feat/m1a-oidc`** (done) — discovery + JWKS, authorize + login transactions +
   password / TOTP + sessions + rate limiting, consent, `authorization_code` /
   `refresh_token` / `client_credentials` grants, userinfo / introspect / revoke
   / logout, background jobs (sweeper, key rotation).
4. **`feat/m1a-management-api`** (done) — management + `me` API
   (`/api/v1`, [contract](api/management.md)), RBAC guards, audit log with
   retention.
5. **`feat/m1a-web`** (done) — login / consent / logout pages, My Account
   (profile, password, TOTP + recovery codes, sessions, consents) and the admin
   center (users, groups, app registrations, role assignments, directory roles,
   audit log, settings, tenants) on the built-in OIDC clients.

## M1b — local auth extras + subdomains (done)

1. **`feat/m1b-subdomains`** (done) — every tenant on its own host
   `{slug}.{PUBLIC_URL host}` (issuer = that origin, path routing removed,
   apex redirects to the system admin center), host-only cookies, per-tenant
   CSRF origin, startup reconcile of built-in SPA URIs, wildcard Ingress.
2. **`feat/m1b-email`** (done) — SMTP outbox, email verification, password reset,
   admin invites, email change, security notifications.
3. **`feat/m1b-passkeys`** (done) — WebAuthn (MFA and passwordless).
4. **`feat/m1b-telegram`** (done) — Telegram bot: linking, sign-in codes (MFA),
   notifications ([telegram.md](telegram.md)).

## M2 — federation + device code

1. **`feat/m2-federation`** (done) — generic upstream OIDC
   ([federation.md](federation.md)): per-tenant identity providers
   (GlobalAdmin-managed, sealed write-only secret), code flow with PKCE /
   `state` / `nonce`, ID token verification, first-sign-in policy
   `jit` / `link_only` / `deny`, explicit linking only (in-flow or My
   Account), optional trust of upstream MFA, home-realm discovery.
2. **`feat/m2-idp-presets`** — Google, Entra (single / multi-tenant with
   a `tid`-templated issuer) and GitHub (OAuth2 adapter).
3. **`feat/m2-device-code`** — device authorization grant (RFC 8628).

## M3 — delegation

Token exchange / on-behalf-of (RFC 8693), admin delegation (app owners, scoped
admin roles), guest users (B2B invites), multi-tenant apps (service
principals), `private_key_jwt` client auth.

## M4 — SAML

SAML 2.0 IdP (enterprise apps) and SAML SP (upstream brokering).

## Later

**Custom domain aliases** for a tenant (e.g. `login.contoso.com` next to
`contoso.{PUBLIC_URL host}`). Decided design: a tenant admin adds them; each
must be globally unique; no DNS ownership proof; a system GlobalAdmin
resolves collisions; an operator adds the ingress host and certificate.
**Blocker:** per-domain certificates (ACME issuance and renewal for hosts
outside the wildcard) must be designed first.
