# oauth

Entra-like multi-tenant identity provider (OAuth 2.1 / OIDC) — Rust, Axum,
SeaORM, PostgreSQL, Vue 3. Work in progress; see [docs/roadmap.md](docs/roadmap.md).

## Quick start

Requires Rust (pinned by `rust-toolchain.toml`), Node 22 (`.nvmrc`) and Docker.

```sh
cp .env.example .env
sed -i "s|^OAUTH_MASTER_KEY=.*|OAUTH_MASTER_KEY=$(openssl rand -base64 32)|" .env
npm ci --prefix web
make dev-db        # Postgres 17 on 127.0.0.1:5432
make web-build     # SPA into web/dist
make run           # http://localhost:8080, metrics on :9090/metrics
```

`make help` lists all targets. `oauth bootstrap` / `make bootstrap` (first
admin) is a stub until M1a step 2. Before pushing: `make lint && make test`
(integration tests start Postgres through testcontainers, so Docker must run).

## Docs

- [Architecture](docs/architecture.md)
- [Roadmap](docs/roadmap.md)
- Deployment: [`deploy/k8s/deploy.yml`](deploy/k8s/deploy.yml), `Dockerfile`
