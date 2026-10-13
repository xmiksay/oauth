# Roadmap

## M1a — core IdP (one branch / PR per step, gate green before push)

1. **`feat/m1a-scaffold`** — Cargo workspace, toolchain pins, Makefile, CI,
   compose, config, error type, health/metrics, migration runner + advisory
   lock, SPA serving, Vue skeleton, Dockerfile, k8s manifests, docs.
2. **`feat/m1a-directory`** (done) — tenants / users / groups / directory roles
   entities + migrations, `keys` module, `oauth bootstrap` CLI, built-in apps
   (`management-api`, `admin-portal`, `my-account`) on tenant creation.
3. **`feat/m1a-oidc`** — discovery + JWKS, authorize + login transactions +
   password / TOTP + sessions + rate limiting, consent, `authorization_code` /
   `refresh_token` / `client_credentials` grants, userinfo / introspect / revoke
   / logout, background jobs (sweeper, key rotation).
4. **`feat/m1a-management-api`** — management + `me` API, RBAC guards, audit.
5. **`feat/m1a-web`** — login, My Account and admin UI.

## M1b — local auth extras + domains

Passkeys / WebAuthn (MFA and passwordless), email verification / reset /
invites (SMTP via lettre), Telegram bot OTP + security notifications,
subdomain and custom-domain tenant routing (`tenant_domains`, DNS TXT
verification).

## M2 — federation

Upstream IdP brokering (generic OIDC, Google, GitHub, Entra; JIT provisioning
and account linking), device code grant (RFC 8628).

## M3 — delegation

Token exchange / on-behalf-of (RFC 8693), admin delegation (app owners, scoped
admin roles), guest users (B2B invites), multi-tenant apps (service
principals), `private_key_jwt` client auth.

## M4 — SAML

SAML 2.0 IdP (enterprise apps) and SAML SP (upstream brokering).
