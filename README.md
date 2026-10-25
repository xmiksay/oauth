# oauth

Entra-like multi-tenant identity provider (OAuth 2.1 / OIDC) — Rust, Axum,
SeaORM, PostgreSQL, Vue 3. Work in progress; see [docs/roadmap.md](docs/roadmap.md).

## Quick start

Requires Rust (pinned by `rust-toolchain.toml`), a C compiler (`cc`; builds
AWS-LC, the crypto provider — no cmake needed), Node 22 (`.nvmrc`) and Docker.

```sh
cp .env.example .env
sed -i "s|^OAUTH_MASTER_KEY=.*|OAUTH_MASTER_KEY=$(openssl rand -base64 32)|" .env
npm ci --prefix web
make dev-db        # Postgres 17 on 127.0.0.1:5432 + Mailpit (inbox http://localhost:8025)
make run           # backend on :8080, metrics on :9090/metrics
make web-dev       # (second terminal) SPA on http://*.localhost:5173
```

Every tenant `t` lives on its own host `t.{PUBLIC_URL host}` (the apex only
redirects to the `system` tenant's admin center). The default `.env` has
`PUBLIC_URL=http://localhost:5173`, the Vite dev server, which proxies the
backend paths with the `Host` header kept; `*.localhost` resolves to loopback
in browsers. Without Vite, `make web-build` and set
`PUBLIC_URL=http://localhost:8080` (then use port 8080 below).

Then create the `system` tenant and its first Global Admin (idempotent; prints
a one-time password that must be changed at first sign-in):

```sh
make bootstrap ADMIN_EMAIL=you@example.com            # RESET=1 re-issues the password
```

With a Telegram bot configured (`TELEGRAM_*`, see `.env.example`), register its
webhook once with `make telegram-webhook` (`oauth telegram set-webhook`).

Sign in at <http://system.localhost:5173/admin> with that password (you are
asked to choose a new one). A tenant created there, say `acme`, is at
<http://acme.localhost:5173/admin>; its issuer is `http://acme.localhost:5173`.

`make help` lists all targets. Before pushing: `make lint && make test`
(integration tests create one database — and for one test a login role — per
test on the Postgres ≥ 17 at `TEST_DATABASE_URL`, default
`postgres://postgres@localhost:5432/postgres`: a TCP URL of a superuser (it
creates and force-drops databases and roles). With `make dev-db` instead, use
`TEST_DATABASE_URL=postgres://oauth:oauth@127.0.0.1:5432/oauth make test`.
Tests run in parallel against one server, so keep `max_connections` at the
default 100 or more. `make test-db-clean` drops what killed runs left behind.
`TEST_DATABASE_URL=` (empty) starts a testcontainers Postgres 17 per test
instead, which needs Docker — CI does that).

## Web UI

One Vue SPA served by the backend on every tenant host `{t}.{PUBLIC_URL host}`:

| URL | What |
|---|---|
| `/` | Dashboard: greeting, tiles for My Account and (with a directory role) the Admin center, quick links; signs in as My Account |
| `/admin` | Admin center (Entra-portal-like): users, groups, app registrations (authentication, secrets, token configuration, expose an API, app roles, API permissions + admin consent), role assignments, directory roles, identity providers, audit log, settings; in the `system` tenant also tenants |
| `/myaccount` | My Account: profile, email, password, authenticator app + recovery codes, passkeys, Telegram, linked accounts, notifications, sessions, app permissions |
| `/login?tx=…` | Sign-in steps (password, passkey or an upstream identity provider → link an unknown identity → authenticator / recovery / Telegram code / passkey → forced password change → consent) |
| `/logout` | Sign-out confirmation / "signed out" page |

Admin center and My Account are the tenant's built-in OIDC clients
(`admin-portal`, `my-account`) and sign in like any other app. The header's app
launcher (grid button) switches between Dashboard, My Account and Admin center.

### Frontend development

`make web-dev` runs Vite on port 5173 for every `*.localhost` host, with HMR,
and proxies API, OIDC and login calls to the backend on :8080 keeping `Host`
(the backend resolves the tenant from it). The login API checks `Origin`
against the tenant's origin, so `PUBLIC_URL` must name the origin the browser
uses. The built-in apps' redirect URIs follow `PUBLIC_URL` (rewritten for every
tenant at each server start), so switching between Vite and backend-only only
needs a restart. `make web-test` runs the vitest suite; `make lint` includes
eslint + vue-tsc (`make lint-rust` / `make lint-web` run one half). Passkeys work on
`http://*.localhost` (browsers treat localhost as a secure context; RP ID =
the tenant host without the port).

## Docs

- [Architecture](docs/architecture.md) — endpoints, flows, token formats, jobs
- [Frontend](docs/frontend.md) — the SPA: areas, auth state, API layer
- [Login JSON API](docs/api/authn.md) — contract for the login SPA
- [Management API](docs/api/management.md) — `/api/v1` REST contract for the admin / My Account SPAs and service apps ([`me`](docs/api/me.md), [identity providers](docs/api/identity_providers.md))
- [Email](docs/email.md) — verification, password reset, invitations, security notices
- [Sign-in](docs/authn.md) — login transactions, stages, `amr`, sessions & CSRF, rate limits
- [Passkeys](docs/passkeys.md) — WebAuthn verifier, passwordless / MFA sign-in, re-authentication
- [Federation](docs/federation.md) — upstream OIDC identity providers: setup, policies, MFA trust, security model
- [Telegram](docs/telegram.md) — bot setup, webhook, sign-in codes, notices
- [Roadmap](docs/roadmap.md)
- [Deployment](docs/deploy.md) — images, environments, CI deploy secrets, release procedure; example manifest [`deploy/k8s/deploy.yml`](deploy/k8s/deploy.yml), `Dockerfile`
