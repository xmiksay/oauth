# Deployment and releases

Images are built by `.github/workflows/ci.yml` and published to
`ghcr.io/xmiksay/oauth`. This repository carries no deployment manifests and
CI never touches a cluster: both environments are Argo CD Applications in the
separate deploy repo `Sourcelab/deploy` (chart `oauth`), whose Image Updater
picks new image tags from GHCR; their Secrets, databases and certificates
belong to the ansible repo `Sourcelab/ansible` (role `oauth`). [`examples/k8s.yml`](examples/k8s.yml) is a non-authoritative example
(ConfigMap, Deployment, Service, PodDisruptionBudget, Ingress) used by nothing
and not tested; the requirements below are what any deployment must meet.

## Deployment requirements

The image runs `oauth serve` as uid 10001 (read-only root filesystem is fine;
it writes nothing to disk). One-off commands use the same image:
`oauth bootstrap --admin-email …` (first Global Admin, prints a one-time
password; `--tenant` / `--provisioning-app` for a regular tenant and a
client-credentials app), `oauth apply -f tenant.yaml` (declarative tenant
state, [provisioning.md](provisioning.md)) and `oauth telegram set-webhook`
(with Telegram).

**Hosts and TLS.** Tenant `t` lives at `t.<PUBLIC_URL host>` and the apex
serves the system redirect (or the [`APEX_TENANT`](#apex-tenant)) and the
Telegram webhook, so DNS and the ingress
need both the apex and a one-label wildcard (`id.example.com`,
`*.id.example.com`) routed to the app, and TLS needs a certificate covering
both (a wildcard certificate can only be issued through ACME DNS-01). Nested
hosts (`a.b.id.example.com`) are never tenants. `PUBLIC_URL` is the external
https origin (no path); `COOKIE_SECURE=false` only with an `http://`
`PUBLIC_URL` (local development).

**Ingress / reverse proxy.** It must pass the client's `Host` (or HTTP/2
`:authority`) through unchanged: the tenant is resolved from it. The server
never reads `X-Forwarded-Host` / `Forwarded`, so a proxy that rewrites `Host`
and relies on those headers to carry the original breaks tenancy (every
request 404s). No shared cache or CDN in front may key responses on the path
without the host. Set `TRUSTED_PROXY_HEADER` (e.g. `X-Forwarded-For`, its
right-most entry is used: exactly one proxy hop) only when such a proxy sets
it; otherwise leave it unset and the TCP peer address is the client IP
(ingress-nginx: keep `use-forwarded-headers` off unless another trusted proxy
sits in front of it). The trust model is in
[http.md](http.md).

**Ports and probes.** `LISTEN_ADDR` (default `0.0.0.0:8080`) serves the app;
`METRICS_ADDR` (default `0.0.0.0:9090`) serves only `GET /metrics`
(Prometheus; includes `oauth_build_info{version,commit}`, see
[Build version and commit](#build-version-and-commit)) and must not be
exposed publicly. Probes on the app port, any
host: liveness `GET /healthz` (process alive, no DB dependency) and readiness
`GET /readyz` (503 until migrations are done, and whenever the DB is
unreachable). No startup probe is needed: the listener opens before
migrations run, so a replica waiting on the migration lock passes liveness
and stays out of the Service. On SIGTERM both listeners drain gracefully;
give the pod a short pre-stop delay (endpoints drop it before it stops
accepting connections) and a termination grace period of at least 75 s
(5 s pre-stop + an outbox send in flight, at most 60 s —
[email.md](email.md#delivery)). The server never calls the Kubernetes API (no
service-account token needed).

**Configuration.** All configuration is environment variables, parsed at
startup (an invalid value fails startup); `.env.example` is the authoritative,
commented list.

| Secret (credentials, keys) | Plain config |
|---|---|
| `DATABASE_URL` (required) | `PUBLIC_URL` (required) |
| `OAUTH_MASTER_KEY` (required; 32 bytes base64) | `LISTEN_ADDR`, `METRICS_ADDR`, `LOG_FORMAT` (`json` in clusters), `RUST_LOG` |
| `SMTP_URL` (with `SMTP_FROM`) | `KEY_ROTATION_DAYS`, `KEY_PREPUBLISH_HOURS`, `SESSION_TTL_HOURS` |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET` (with `TELEGRAM_BOT_USERNAME`) | `COOKIE_SECURE`, `TRUSTED_PROXY_HEADER`, `WEB_DIST_DIR` |
| | `SMTP_FROM`, `TELEGRAM_BOT_USERNAME`, `TELEGRAM_API_URL` |
| | `SYSTEM_TENANT_SLUG` (default `system`), `SYSTEM_TENANT_RENAME` (`1` / `0`, default `0`) |
| | `APEX_TENANT` (unset) |

Email is on only with both `SMTP_URL` and `SMTP_FROM`, Telegram only with all
three `TELEGRAM_*` above; a partial set fails startup. Back up
`OAUTH_MASTER_KEY`: it seals the signing keys, TOTP secrets, upstream IdP
client secrets and queued messages, and losing it makes them unreadable.

<a id="system-tenant-slug"></a>**System tenant slug.** The tenant that manages
the others lives at `<SYSTEM_TENANT_SLUG>.<PUBLIC_URL host>` (default
`system`); the apex redirects to its `/admin`. Pick it before the first
`oauth bootstrap`, which creates the tenant under that slug. It must be a
valid tenant slug that is not on the reserved list (`www`, `api`, `admin`, …);
`system` itself stays reserved for regular tenants even after the system
tenant moved away from it, so nobody can take over its old host. Changing it
later: a replica (or `oauth bootstrap`) whose `SYSTEM_TENANT_SLUG` differs
from the stored system tenant's slug refuses to start, naming both. Set
`SYSTEM_TENANT_RENAME=1` to rename instead: startup renames the system tenant
in the migration transaction (refused if another tenant already has the slug),
retires the old slug (above), audits it as `tenant.rename` (actor `system`, details `from`, `to`, `via`:
`startup` or `bootstrap`) and points
its built-in SPAs' redirect URIs at the new host. **Renaming changes the
system tenant's host and therefore its issuer**: the old host answers 404,
tokens it issued name the old issuer and stop validating, its browser
sessions (host-only cookies) stay behind on the old host, its users' passkeys
(bound to the host as RP ID) no longer work — users sign in with a password
or a linked identity and enrol new ones (a passkey-only user needs a password
reset by another Global Admin) — and relying parties registered in the system
tenant, and upstream identity providers holding its federation callback URL,
must be updated to the new host. Roll the
change out with every replica on the new value (a replica still on the old
one refuses to start once the rename committed); the flag is a no-op once the
slugs agree. Every slug the system tenant gives up stays reserved for good:
the rename records it in `retired_tenant_slugs` in the same transaction, so
no regular tenant can claim the host and issuer its former users, relying
parties and upstream IdPs still know (creating one is a 400 `reserved`,
startup refuses an enabled tenant holding one — e.g. created before this
check existed — and such a tenant is never served; disable it to start).
The system tenant itself may move back to a slug it gave up. The table is
append-only and holds only the system tenant's slugs (a trigger refuses
anything else). Renames that ran before it existed are backfilled when the
migration creates it, from the system tenant's `tenant.rename` audit events
(`details.from`); a rename whose audit row already fell to the system
tenant's `audit_retention_days` can't be recovered — such a slug is **not**
reserved, so check that no regular tenant should be on it. Conversely, an
enabled regular tenant that took a backfilled slug makes startup refuse to
run after the upgrade until it is disabled or renamed.

<a id="apex-tenant"></a>**Apex tenant.** By default the apex (`PUBLIC_URL`
itself) only redirects `GET /` to the system tenant's admin center. Set
`APEX_TENANT=<slug>` to serve one regular tenant there instead — e.g. the
production tenant at `https://id.example.com` rather than
`https://prod.id.example.com`. That tenant then lives **only** on the apex:
its issuer, discovery, JWKS, every protocol, login and management endpoint,
the SPA (`/`, `/login`, `/logout`, `/device`, `/myaccount`, `/admin`), its
cookies (host-only, so they stay on the apex), the login API's CSRF origin,
CORS, back-channel logout `iss`, federation callback URL
(`{PUBLIC_URL}/federation/callback`), email / notice links and its passkey RP
ID (the apex host) all use the apex origin, and its old subdomain answers 404.
Other tenants, the system tenant included, stay on their subdomains;
`/telegram/webhook` stays a reserved apex path and the probes answer on any
host. Startup refuses a slug that is not a regular tenant slug, is the system
tenant's, names no tenant, or names a disabled one, so create the tenant first
(with `APEX_TENANT` unset) and then set it on every replica; while it is set,
the tenant can't be disabled (403). Unset = the default redirect.
Startup points the tenant's built-in SPAs' redirect URIs at the apex (and back
when unset). **Moving an existing tenant to or from the apex changes its
issuer and origin**, with the same consequences as a
[system tenant rename](#system-tenant-slug): tokens it issued stop validating,
browser sessions stay behind, passkeys (bound to the old host as RP ID) stop
working, and relying parties and upstream identity providers (federation
callback URL) must be updated. A passkey registered on the apex names the apex
host as RP ID, which browsers would also accept on its subdomains; the server
still verifies the RP ID hash and the exact origin per tenant, so it is only
ever accepted by the apex tenant.

**Database.** One PostgreSQL database shared by all replicas; it holds all
state (sessions, codes, login transactions, rate limits), so the app is
otherwise stateless and needs no sticky sessions or volumes. The
`DATABASE_URL` role needs DDL rights on it: every replica runs pending migrations on
startup, all in one transaction holding `pg_advisory_xact_lock`, so
concurrent starts serialize and a failed migration rolls back and exits
non-zero. There is no separate migration job. A migration that can refuse
existing data is listed under [Upgrade notes](#upgrade-notes): run its
pre-check before rolling out, or the new pods crash-loop until the data is
fixed (the old ones keep serving).

**Replicas.** Any number of replicas is safe, and two or more (with a
disruption budget keeping one available) avoid downtime on rollouts and node
drains. Background jobs (key rotation, cleanup, outbox delivery) take a
per-run advisory lock, so only one replica does each run.

## CI jobs

| Job | Runs on | Does |
|---|---|---|
| `gate` | PR, push to `main`, `v*` tag | `make lint`, `make test`, `make web-build` |
| `docker` | same | builds the `Dockerfile` (no push), writes the GHA layer cache |
| `publish` | push to `main`, `v*` tag (this repo only, never PRs) | after `gate` + `docker`: builds and pushes |

Runs are serialised per ref (`concurrency: ci-<ref>`), so images are
published in push order. A new push to a PR cancels its running
run. On `main` and tags at most one run waits behind the running one: a newer
push supersedes that pending run, so not every push to `main` gets a gate run
or a `:sha-` image.

Image tags:

- push to `main` → `:main`, `:sha-<7-char commit>` and
  `:main-<YYYYMMDDHHmmss>`, built from the GHA layer cache the `docker` job
  just wrote. The timestamp is the commit's committer time in UTC, so a re-run
  republishes the same tag and newer `main` commits sort after older ones
  (the job fails if `HEAD`'s committer time is earlier than its parent's).
  Test follows the newest of these tags.
- tag `vX.Y.Z` → `:X.Y.Z` only, built with `no-cache`. The GHA cache is
  ref-isolated (a PR's cache is visible only to that PR), so this is defence in
  depth: a release is a clean build that never reuses layers written by other
  runs, including `main` runs a compromised action or dependency could have
  poisoned. Before
  anything is pushed the job fails unless:
  - `X.Y.Z` equals `[workspace.package] version` in the root `Cargo.toml`;
  - the tagged commit is on `main` (`git merge-base --is-ancestor`);
  - `:X.Y.Z` does not exist in GHCR yet (release tags are never overwritten;
    any registry answer other than 404 also fails the job).

No `:latest`. Images carry the OCI labels from `docker/metadata-action`
(`org.opencontainers.image.source`, `revision`, `version`, `created`, …).

### Build version and commit

`docker` and `publish` pass `--build-arg GIT_SHA=${{ github.sha }}`; the
Dockerfile turns it into the `GIT_SHA` env of the `cargo build`, and
`crates/server/build.rs` bakes its first 12 hex digits into the binary (the
build context has no `.git`, so an image built without the arg reports
`unknown`; `make docker` passes the checkout's HEAD). Outside Docker,
`build.rs` falls back to `git rev-parse --short=12 HEAD`, then `unknown`.
The workspace version and that commit show up in:

- `oauth --version` → `oauth X.Y.Z (<commit>)`;
- the `serve` startup log (`version`, `commit` fields);
- the metric `oauth_build_info{version="X.Y.Z",commit="<commit>"} 1` on
  `METRICS_ADDR` — one series, both labels build constants;
- the SPA footer (`vX.Y.Z · <commit>`), from the `oauth-build` `<meta>` the
  server writes into `index.html`, so it always names the serving binary.

## Environments

| Environment | URL | Argo CD Application | Image |
|---|---|---|---|
| test | https://test.oauth.cz (namespace `services`) | `oauth-test` | newest `:main-<YYYYMMDDHHmmss>` |
| production | https://oauth.cz (namespace `services`) | `oauth` | newest `:X.Y.Z` (release tags only) |

Both are Applications of chart `oauth` in `Sourcelab/deploy` (automated sync
with prune and self-heal). Argo CD Image Updater watches GHCR (package webhook
of this repo, plus polling) and sets the newest allowed tag on the Application;
Argo then rolls the Deployment. Nothing in this repository deploys, and nobody
should `kubectl set image` either: Argo's self-heal reverts it. To pin or roll
back, follow *Pin or roll back* in the deploy repo's README. Argo CD's own
sign-in goes through production, so a broken production rollout is fixed with
`kubectl` against the Application, not the Argo UI.

## Repository setup (one-time, by an admin)

### Release tag ruleset

Only admins may create `v*` tags, and nobody may move or delete one:

```sh
gh api -X POST repos/xmiksay/oauth/rulesets --input - <<'EOF'
{
  "name": "release tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
  "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}],
  "bypass_actors": [
    {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
  ]
}
EOF
```

`creation` limits tag creation to the bypass list (repository role 5 =
Admin). Update and deletion are blocked for everyone else. Admins can still
bypass them, so do not move a pushed tag: CI refuses to republish an existing
`:X.Y.Z` anyway.

### Make the package public

New GHCR packages are private, and the cluster pulls (and Image Updater
lists tags) without credentials. So right after the first `main` publish
creates the package, and before any cluster can pull it, make it public:
GitHub → the `oauth` package → *Package settings* → *Change visibility* →
Public. (Also check *Manage Actions access* lists `xmiksay/oauth` with write
access.)

Push the first `v*` tag only after a `main` publish has created the package.
Before that, the release tag's registry check fails closed (403); re-run it
once `main` has published.

### Package webhook

Image Updater learns about a pushed image from this repository's `package`
webhook, which `make argocd-github-hooks` in `Sourcelab/ansible` creates (its
secret never leaves that repo's vault); without it, Image Updater still finds
new tags on its polling interval. The repository needs no Actions secrets and
no deployment environment: CI only reads code and writes packages.

## Release procedure

1. On a branch, bump `version` under `[workspace.package]` in `Cargo.toml`,
   run `make build` (or `cargo check`) to update `Cargo.lock` (it records the
   workspace version and the Dockerfile builds with `--locked`), and commit
   both in the same PR; merge it to `main`.
2. As an admin, tag the merged commit on `main` and push the tag:

   ```sh
   git tag -a vX.Y.Z -m vX.Y.Z
   git push origin vX.Y.Z
   ```

3. Wait for `publish` to push `ghcr.io/xmiksay/oauth:X.Y.Z`. A mistake (wrong
   version, commit not on `main`, version already published) fails before
   pushing: fix it and release the next version rather than moving the tag.
4. Nothing else: Argo CD Image Updater sees the new `X.Y.Z` (GHCR webhook or
   its polling) and Argo rolls production out. Follow it in Argo CD
   (Application `oauth`) or with
   `kubectl -n services rollout status deployment/oauth`. Run any pre-check
   from [Upgrade notes](#upgrade-notes) **before** pushing the tag.

## Upgrade notes

### Case-insensitively unique group names (migration `m20261121_000011_group_names`)

This release adds a unique index on group names per tenant, ignoring letter
case, so names can go in the `groups` claim. Duplicates are never renamed
for you: if two groups of one tenant differ only in case (`Ops` / `ops`), the
migration aborts, lists the colliding groups (tenant slug, name, id) in its
error and every new pod exits non-zero. Before upgrading, find them with:

```sql
SELECT t.slug, lower(g.display_name) AS name, array_agg(g.id ORDER BY g.id) AS ids
FROM groups g JOIN tenants t ON t.id = g.tenant_id
GROUP BY t.slug, g.tenant_id, lower(g.display_name)
HAVING count(*) > 1;
```

and rename all but one group of each row, through the admin UI /
`PATCH /api/v1/groups/{id}` or directly:

```sql
UPDATE groups SET display_name = '<new name>', updated_at = now() WHERE id = '<id>';
```

An empty result means the upgrade is safe. The older version keeps accepting
colliding names until the new one runs, so check again right before the
rollout; if it still fails, rename the groups it lists and let the pods
restart.
