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
make dev-db        # Postgres 17 on 127.0.0.1:5432
make web-build     # SPA into web/dist
make run           # http://localhost:8080, metrics on :9090/metrics
```

Then create the `system` tenant and its first Global Admin (idempotent; prints
a one-time password that must be changed at first sign-in):

```sh
make bootstrap ADMIN_EMAIL=you@example.com            # RESET=1 re-issues the password
```

Sign in at <http://localhost:8080/system/admin> with that password (you are
asked to choose a new one).

`make help` lists all targets. Before pushing: `make lint && make test`
(integration tests start Postgres through testcontainers, so Docker must run).

## Web UI

One Vue SPA served by the backend, per tenant `{t}`:

| URL | What |
|---|---|
| `/{t}/admin` | Admin center (Entra-portal-like): users, groups, app registrations (authentication, secrets, token configuration, expose an API, app roles, API permissions + admin consent), role assignments, directory roles, audit log, settings; in the `system` tenant also tenants |
| `/{t}/myaccount` | My Account: profile, password, authenticator app + recovery codes, sessions, app permissions |
| `/{t}/login?tx=…` | Sign-in steps (password → authenticator / recovery code → forced password change → consent) |
| `/{t}/logout` | Sign-out confirmation / "signed out" page |

Admin center and My Account are the tenant's built-in OIDC clients
(`admin-portal`, `my-account`) and sign in like any other app.

### Frontend development

`make web-dev` runs Vite (http://localhost:5173) with HMR and proxies API,
OIDC and login calls to the backend on :8080. The login API checks `Origin`
against `PUBLIC_URL`, and the built-in apps' redirect URIs are registered from
`PUBLIC_URL` when a tenant is created, so for Vite set
`PUBLIC_URL=http://localhost:5173` in `.env` **before** `make bootstrap` (or
use a fresh database). `make web-test` runs the vitest suite; `make lint`
includes eslint + vue-tsc.

## Docs

- [Architecture](docs/architecture.md) — endpoints, flows, token formats, jobs
- [Login JSON API](docs/api/authn.md) — contract for the login SPA
- [Management API](docs/api/management.md) — `/api/v1` REST contract for the admin / My Account SPAs and service apps
- [Roadmap](docs/roadmap.md)
- Deployment: [`deploy/k8s/deploy.yml`](deploy/k8s/deploy.yml), `Dockerfile`
