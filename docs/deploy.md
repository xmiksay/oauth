# Deployment and releases

Images are built by `.github/workflows/ci.yml` and published to
`ghcr.io/xmiksay/oauth`. This repository carries no deployment manifests:
both environments' Kubernetes objects are owned by the ansible repo
`Sourcelab/ansible`, role `oauth`; CI's `deploy-test` job only swaps the image
digest of the existing `oauth-test` Deployment. [`examples/k8s.yml`](examples/k8s.yml) is a non-authoritative example
(ConfigMap, Deployment, Service, PodDisruptionBudget, Ingress) used by nothing
and not tested; the requirements below are what any deployment must meet.

## Deployment requirements

The image runs `oauth serve` as uid 10001 (read-only root filesystem is fine;
it writes nothing to disk). One-off commands use the same image:
`oauth bootstrap --admin-email …` (first Global Admin, prints a one-time
password) and `oauth telegram set-webhook` (with Telegram).

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
(Prometheus) and must not be exposed publicly. Probes on the app port, any
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
The system tenant itself may move back to a slug it gave up.

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
| `publish` | push to `main`, `v*` tag (this repo only, never PRs) | after `gate` + `docker`: builds and pushes; job output `digest` |
| `deploy-test` | push to `main` | after `publish`: rolls the pushed digest out to deployment `oauth-test` in namespace `services` |

Runs are serialised per ref (`concurrency: ci-<ref>`), so images are
published and deployed in push order. A new push to a PR cancels its running
run. On `main` and tags at most one run waits behind the running one: a newer
push supersedes that pending run, so not every push to `main` gets a gate run
or a `:sha-` image.

Image tags:

- push to `main` → `:main` and `:sha-<7-char commit>`, built from the GHA
  layer cache the `docker` job just wrote.
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

## Environments

| Environment | URL | Image | Rolled out by |
|---|---|---|---|
| test | https://test.oauth.cz (deployment `oauth-test`, namespace `services`) | `main`, by digest | CI job `deploy-test` on every push to `main` |
| production | https://oauth.cz | `:X.Y.Z` from a `v*` tag | ansible: bump `oauth_version` in the `oauth` role, then `make services SERVICE=oauth` in `Sourcelab/ansible` |

`deploy-test` runs in the GitHub environment `test` with
`concurrency: deploy-test` (deploys queue, never cancel each other). It runs
`kubectl -n services set image deployment/oauth-test oauth=ghcr.io/xmiksay/oauth@<digest>`
and waits for `kubectl -n services rollout status deployment/oauth-test`
(10 min timeout). Both touch only that Deployment, which is all CI's Role
allows. Deploying by digest means test runs exactly the image that job published, even if `:main` has moved
since. A job whose commit is no longer the tip of `main` (`git ls-remote`),
e.g. a re-run of an old run, skips the rollout with a notice instead of
rolling test back. Ansible must not pin the test Deployment's image, or the
next ansible run reverts CI's rollout.

## Repository setup (one-time, by an admin)

### `test` environment

Create it and allow deployments from `main` only, so the environment secrets
are unreachable from any other branch:

```sh
gh api -X PUT repos/xmiksay/oauth/environments/test --input - <<'EOF'
{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
EOF
gh api -X POST repos/xmiksay/oauth/environments/test/deployment-branch-policies \
  -f name=main -f type=branch
```

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

New GHCR packages are private, and the clusters pull without an image pull
secret (the policy on the `oauth-test` Deployment forbids CI from adding
`imagePullSecrets`).
So right after the first `main` publish creates the package, and before any
cluster can pull it, make it public: GitHub → the `oauth` package →
*Package settings* → *Change visibility* → Public. (Also check *Manage Actions
access* lists `xmiksay/oauth` with write access.) That first `deploy-test`
cannot pull the private image and fails; re-run it once the package is
public.

Push the first `v*` tag only after a `main` publish has created the package.
Before that, the release tag's registry check fails closed (403); re-run it
once `main` has published.

## Deploy secrets

The Kubernetes API (`https://172.16.16.1:6443`) is reachable only over the
WireGuard hub, so `deploy-test` needs two **environment secrets of `test`**
(not repository secrets: only jobs in that environment, on `main`, can read
them). If either is missing (forks, a fresh setup) the job logs a notice and
skips every step.

| Secret | Content |
|---|---|
| `WG_CONFIG` | a complete `wg-quick` client config for the CI peer |
| `KUBE_CONFIG` | base64 kubeconfig of service account `oauth-ci` in `services` |

### `WG_CONFIG`

1. Create a peer by hand in wireguard-ui on the hub. Set `AllowedIPs` to
   `172.16.16.1/32` (only the API — the runner's other traffic must not use the
   tunnel) and leave out `DNS =` (the runner has no `resolvconf`, and the API
   is addressed by IP).
2. In the ansible repo, restrict that peer's IP in the firewall to the API
   port only (tcp 6443 on 172.16.16.1).
3. Download the peer config and store it:

   ```sh
   gh secret set WG_CONFIG --env test -R xmiksay/oauth < peer.conf
   rm peer.conf
   ```

### `KUBE_CONFIG`

In `Sourcelab/ansible`. The service account's Role is limited by
`resourceNames` to the `oauth-test` Deployment in `services`; `set image` and
`rollout status` need `get`, `patch`, `list` and `watch` on it. It cannot read
pods or replicasets, so the job must not touch anything else:

```sh
make kubeconfig-sa NS=services SA=oauth-ci | base64 -w0 | gh secret set KUBE_CONFIG --env test -R xmiksay/oauth
```

### How CI handles them

Secrets reach steps only as environment variables, never on a command line
and never echoed (no `set -x`). `WG_CONFIG` is written to
`/etc/wireguard/wg0.conf` under `umask 077`, `KUBE_CONFIG` is decoded to a
mode-600 file in `$RUNNER_TEMP`. A final `if: always()` step brings `wg0`
down and deletes both files. kubectl is a pinned version whose SHA-256 is
pinned in the workflow and checked before install.

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
4. In `Sourcelab/ansible`, bump `oauth_version` to `X.Y.Z` in the `oauth`
   role and run `make services SERVICE=oauth`.

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
