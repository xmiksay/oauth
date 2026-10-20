# Deployment and releases

Images are built by `.github/workflows/ci.yml` and published to
`ghcr.io/xmiksay/oauth`. `deploy/k8s/deploy.yml` is a generic example
manifest; the real deployments (both environments) are managed by the
ansible repo `Sourcelab/ansible`, role `oauth`.

## CI jobs

| Job | Runs on | Does |
|---|---|---|
| `gate` | PR, push to `main`, `v*` tag | `make lint`, `make test`, `make web-build` |
| `docker` | same | builds the `Dockerfile` (no push), writes the GHA layer cache |
| `publish` | push to `main`, `v*` tag (this repo only, never PRs) | after `gate` + `docker`: builds and pushes; job output `digest` |
| `deploy-test` | push to `main` | after `publish`: rolls the pushed digest out to `oauth-test` |

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
| test | https://test.oauth.cz (namespace `oauth-test`) | `main`, by digest | CI job `deploy-test` on every push to `main` |
| production | https://oauth.cz | `:X.Y.Z` from a `v*` tag | ansible: bump `oauth_version` in the `oauth` role, then `make services SERVICE=oauth` in `Sourcelab/ansible` |

`deploy-test` runs in the GitHub environment `test` with
`concurrency: deploy-test` (deploys queue, never cancel each other). It runs
`kubectl -n oauth-test set image deployment/oauth oauth=ghcr.io/xmiksay/oauth@<digest>`
and waits for `rollout status` (10 min timeout). Deploying by digest means the
namespace runs exactly the image that job published, even if `:main` has moved
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
secret (the `oauth-test` policy forbids CI from adding `imagePullSecrets`).
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
| `KUBE_CONFIG` | base64 kubeconfig of service account `ci` in `oauth-test` |

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

In `Sourcelab/ansible` (the service account's RBAC lets it patch / watch only
the `oauth` Deployment in `oauth-test`):

```sh
make kubeconfig-sa NS=oauth-test SA=ci | base64 -w0 | gh secret set KUBE_CONFIG --env test -R xmiksay/oauth
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
