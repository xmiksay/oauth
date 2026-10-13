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

`make help` lists all targets. Before pushing: `make lint && make test`
(integration tests start Postgres through testcontainers, so Docker must run).

## Docs

- [Architecture](docs/architecture.md) — endpoints, flows, token formats, jobs
- [Login JSON API](docs/api/authn.md) — contract for the login SPA
- [Management API](docs/api/management.md) — `/api/v1` REST contract for the admin / My Account SPAs and service apps
- [Roadmap](docs/roadmap.md)
- Deployment: [`deploy/k8s/deploy.yml`](deploy/k8s/deploy.yml), `Dockerfile`
