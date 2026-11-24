# Declarative provisioning

Two CLI commands, both with direct database access (`DATABASE_URL`,
`OAUTH_MASTER_KEY`, `PUBLIC_URL` from the environment, like `oauth serve`),
let a Kubernetes Job or CI pipeline set up a tenant without a manual UI step:

- `oauth bootstrap` creates the tenant (and its first Global Admin and / or a
  provisioning app);
- `oauth apply -f tenant.yaml` keeps the tenant's desired state, kept in Git,
  in sync.

## `oauth bootstrap`

```sh
oauth bootstrap [--tenant <slug> [--tenant-name <name>]]
                [--admin-email <email> [--display-name <name>] [--reset-password]]
                [--provisioning-app <client_id> [--provisioning-role read|read-write] [--rotate-secret] [--adopt-app]]
# make bootstrap [TENANT=… [TENANT_NAME=…]] [ADMIN_EMAIL=… [DISPLAY_NAME=…] [RESET=1]] [PROVISIONING_APP=… [PROVISIONING_ROLE=…] [ROTATE=1] [ADOPT=1]]
```

Idempotent, migrates first, runs in one transaction holding the bootstrap
advisory lock. At least one of `--admin-email` / `--provisioning-app`.

- Without `--tenant` it works on the system tenant (`SYSTEM_TENANT_SLUG`, default
  `system`; created when missing, its stored slug reconciled like `serve` does).
  `--tenant <slug>` works on that regular tenant instead, creating it (slug
  rules of `POST /api/v1/tenants`, signing keys, built-in apps) when missing;
  the system tenant is not created on the way.
- `--admin-email`: as before — the user is created with a one-time password
  (printed once) and made a Global Admin.
- `--provisioning-app <client_id>`: a confidential app (display name
  `Provisioning`) assigned the management API app role
  `Directory.ReadWrite.All` (default, `read-write`) or `Directory.Read.All`
  (`read`). The app holds exactly the requested one: re-running with the
  other `--provisioning-role` removes the role it held before (re-running
  with `read` downgrades a `read-write` app, and says so; the way back up
  needs `--adopt-app`, see below). A client secret (180 days) is issued and printed **once** — when
  the app is created, or again with `--rotate-secret` (older secrets stay
  valid until they expire or are deleted). The app gets a token with
  `client_credentials` and `scope=api://management-api/.default` on the
  tenant's host. Because the app holds management API access only a Global
  Admin can change its credentials or redirect URIs.
- An **existing** app is a takeover when bootstrap would hand it more than
  it has or act on behalf of someone else's app. Holding a role doesn't mean
  an earlier bootstrap made the app — a Global Admin (`POST
  /api/v1/role-assignments`) or `oauth apply` can give either role to any
  confidential app, e.g. a read-only audit-export app. Bootstrap recognises
  an app it made (or adopted) by a client secret described `oauth bootstrap`
  (every secret it issues carries it; secrets aren't swept on expiry). That
  marker guards against typos, not against admins: whoever can add a secret
  to an app already controls it. Takeovers:
  - the app holds neither role;
  - it holds only `Directory.Read.All` and `read-write` (the default) is
    requested — an upgrade, even of a bootstrap-made app;
  - without the marker: `read` is requested of a `read-write` app (a
    downgrade would break a third party's app), or `--rotate-secret` is given
    (the new secret would let the operator act as someone else's app).

  A takeover is refused, before anything is written, unless `--adopt-app` is
  given — a mistyped client_id must not hand someone's app the management
  API (or write access to it), change its access, or give out a secret for
  it. With the flag the report starts with a `WARNING:` line saying which
  takeover it was (adopted / upgraded / downgraded / issuing a secret). An
  app already holding the requested role needs no flag (nor, with the
  marker, a downgrade or `--rotate-secret`). Every change of an existing
  app's role — assigned or removed — is printed as a `WARNING:` line.
- **What the provisioning app may do.** Its "scoped directory role" is the
  management API app role, not a directory role (directory roles are held
  by users only), and `authz` scopes it as follows. `read-write` writes
  users, groups, memberships, applications (scopes, roles, required
  permissions, secrets of other apps, app role assignments) and consents,
  and reads directory role assignments and the audit log; `read` only
  reads those. It can **never** assign or remove directory roles and has
  no access to identity providers at all: those need `oauth apply` or a
  Global Admin.

Its audit events have `actor_type: system`: `tenant.create` (in the new
tenant's own log), `application.create`, `application.secret_add` and
`app_role_assignment.create` / `app_role_assignment.delete`.

## `oauth apply`

```sh
oauth apply -f tenant.yaml [--dry-run]
# make apply FILE=tenant.yaml [DRY_RUN=1]
```

The file declares **one existing tenant** (`tenant: <slug>`; create it with
`oauth bootstrap --tenant`). Apply needs a migrated schema but never
migrates itself (a dry run changes nothing): when a migration of the binary
is pending it stops before any write and says to run `oauth serve` or
`oauth bootstrap` first. Example: [examples/tenant.yaml](examples/tenant.yaml).

**One transaction.** Everything runs in one database transaction holding a
per-tenant advisory lock (concurrent applies of a tenant serialize): the file
applies completely or not at all. `--dry-run` runs exactly the same steps and
rolls back, so its output is exactly what an apply would change. Right after
that lock it takes every identity provider of the tenant `FOR UPDATE` (in id
order), before it touches any user: the global lock order is IdP → user, and
a federated sign-in holds its provider `FOR SHARE` while it locks the user
and writes mapped memberships. Sign-ins through the tenant's providers wait
for the apply to finish (they never deadlock with it), and no group mapping
changes a membership while apply reads and releases it. A `--dry-run` takes
the same locks, so it blocks those sign-ins (and IdP edits through the
management API) just the same, for as long as the run takes: hashing
`password_env` passwords with argon2 makes that noticeable. An IdP the file
declares that the management API creates while apply runs (after these locks)
stops the apply with an error, rather than being locked after users: run it
again.

**Applications.** The global lock order is IdP → user → application →
consent / session → tokens: a token request locks its user, then its client
and resource apps `FOR KEY SHARE`, then consent, session, code and token
rows ([backchannel_logout.md](backchannel_logout.md)).

Apply locks each declared existing app only `FOR NO KEY UPDATE`, which
serializes it with other writers of the app but not with token requests:
code redemptions and refreshes for declared apps keep working while apply
(or a dry run) runs, unless they need a user apply has locked. Apps it
deletes, and apps whose `identifier_uri` it changes (a key column), are
locked `FOR UPDATE`: token requests for those wait for the apply to finish
and then fail with `invalid_grant` if the app is gone.

Apply takes these locks in the same order. It first locks every user it
writes `FOR UPDATE`: directory role changes, the undeclared users it deletes
at the end, then the users it disables (all of them before it revokes the
first one's sessions and tokens). Then it locks every existing app it writes
or deletes, in id order (`provision::apps::lock`). Only after that does it
write any application, required permission, consent or role assignment; the
only session and token rows it touches before are those of users it already
holds. So it never holds an app, consent, session or token row while waiting
for a user or an app a token request holds: on user and application locks it
never deadlocks with one. Login completion (issuing the authorization code or
approving a device request), the device code grant and the management API's
admin consent grant lock their apps the same way, so deleting an app never
deadlocks with them either. An existing app the file declares that the
management API creates while apply runs (after `provision::apps::lock`)
stops the apply with an error, rather than being locked out of order: run it
again.

Below applications, consents come before tokens: a multi-resource refresh
locks its consent rows (the user's grant and the admin grant of a client /
resource pair) `FOR SHARE` in id order, then its refresh token. Apply writes
consent rows in several statements (one per removed scope, then the admin
consents), so right after the app locks it locks every grant it may write
`FOR UPDATE` in one statement, in id order (`provision::grant_locks`): every
grant of an app it locked and every admin grant of the tenant. Its later
consent writes only take locks it already holds; a grant the management API
or a sign-in creates while apply runs (after that lock) that apply would
write stops the apply with an error: run it again. Apply drops
removed scopes from consent grants (as `DELETE …/scopes/{id}` does, which
rewrites the grants before it revokes) and deletes narrowed or undeclared
admin consents in place, but revokes the tokens of those scopes and grants
only after its last consent write (`provision::consents::revoke_tokens`).
Before that it touches only the tokens of users it holds (disabling); after
it, deleting apps and users cascades only to consents of apps it holds
`FOR UPDATE` and users it holds, which a refresh locks before any consent.
So it never holds a token row while it waits for a consent row a refresh
holds.

Output lines:
`+` created, `~` updated, `-` deleted. A `~` line lists each changed field
with its stored and its new value, as SQL literals
(`~ application web: redirect_uris: ARRAY ['https://a/cb'] -> ARRAY ['https://b/cb']`),
plus `adopted` when an existing object is taken over. Secrets never appear:
a newly set IdP client secret shows as `client_secret: set`.

**Matching and adoption.** Objects are matched by natural key: users by
email (case-insensitive), groups by name (case-insensitive), identity
providers by name, applications by `client_id`, scopes and roles by value
within their app, required permissions by (resource, type, value), role
assignments by (role, principal), admin consents by (client, resource). A
declared object that already exists — created through the API, the admin UI
or an earlier apply — is updated and **adopted**: it is marked
`managed = true` (as `managed` in the management API on every kind but
group memberships; the admin UI shows *Managed by apply* on users, groups,
applications and identity providers).

**Deletion.** Only managed objects the file no longer declares are deleted;
objects apply never created or adopted are never touched. Lists are the
complete desired set of managed objects: a list left out means "none". So
removing a user from the file deletes that user if apply manages it, and an
empty file (`tenant: contoso`) deletes every managed object of the tenant.

**Scalars.** An optional setting left out keeps the stored value (on create:
the management API's default). `null` clears a nullable one
(`identifier_uri`, `backchannel_logout_uri`, `discovery_url`, `mfa_acr`,
`hosted_domain`).

**Validation** is the management API's: the same validators and write
helpers (`api::app_body`, `api::validate`, `api::idp_body`,
`api::role_assignments`, …), the same per-app caps, the last-Global-Admin
rule (removing, disabling or deleting the last enabled Global Admin fails;
it is checked on the end state, so one file may promote a new Global Admin
and disable or demote the old one). Disabling a user revokes their sessions
and refresh tokens, like `PATCH /api/v1/users/{id}`; disabling and deleting
both queue the Back-Channel Logouts of the ended sessions (deletion through
the same `directory::delete_user` as `DELETE /api/v1/users/{id}`). Users are
locked (`FOR UPDATE`) before they are deleted or lose a directory role, and
the `UPDATE` that disables one row-locks it, like the API, so a concurrent
sign-in serializes with it; a disabled user's sessions and refresh tokens
are revoked after the end-state Global Admin check, so a sign-in that
finished first has its session ended too. Identity provider updates go through the API's own
`api::idp_update`: narrowing `allowed_tenants` / `hosted_domain` bumps the
provider's generation (a callback verified against the wider rule fails)
and drops the memberships its group mappings gave, and opening a provider
that has group mappings to every Entra tenant is refused.
Apply acts with full trust (like a Global Admin): it may assign management
API roles and change apps that hold them. The schema is strict: unknown
fields, duplicate keys and a role assignment without exactly one principal
are errors before anything is written. So is a reference (group member,
directory role, role assignment, required permission, admin consent) to a
user, group or app that apply manages but the file no longer declares: it
would be created and then deleted with its target in the same run. Files
are limited to 4 MiB (the CLI never reads more than that).

**Audit.** Every change is audited like its API counterpart, with
`actor_type: apply` (no actor id, no IP). Adoption alone (only the marker
changes) is listed but not audited.

### Schema

```yaml
tenant: <slug>                       # required
users:                               # by email
  - email: a@example.com             # case and surrounding whitespace ignored
    display_name: A                  # required
    password_env: OAUTH_APPLY_A_PW   # optional; initial password, only on create
    must_change_password: true       # optional; only with password_env, only on
                                     # create (default true, like the API)
    disabled: false                  # optional
groups:                              # by display_name (case-insensitive)
  - display_name: Engineers
    description: …                   # optional
    members: [a@example.com]         # emails of existing or declared users
identity_providers:                  # by name
  - name: Corporate SSO
    kind: oidc|google|entra|github   # optional (default oidc), fixed after create
    issuer: https://login.corp.example   # required for oidc / entra; presets
                                         # google / github default it
    client_id: …
    client_secret_env: OAUTH_APPLY_SSO_SECRET  # optional; set only while the
                                     # IdP has no secret
                                     # (github needs one)
    discovery_url, client_auth, scopes, policy, trust_upstream_mfa, mfa_acr,
    email_domains, hosted_domain, allowed_tenants, trust_upstream_email,
    enabled, visible                 # optional, as in the management API
applications:                        # by client_id; built-in apps can't be declared
  - client_id: web
    display_name: Web                # required
    client_type: confidential|public # optional (default confidential), fixed after create
    redirect_uris, post_logout_redirect_uris, web_origins, identifier_uri,
    access_token_format, signing_alg, groups_claim_format, id_token_groups,
    assignment_required, access_token_ttl_secs, refresh_token_ttl_secs,
    device_code_enabled, mfa_policy,
    backchannel_logout_uri,          # nullable: `null` clears it
    backchannel_logout_session_required  # optional, as in the API
    scopes:
      - { value: Orders.Read, description: …, admin_consent_required: false }
    roles:
      - { value: Orders.Admin, display_name: …, description: …, allowed_member_types: [user] }
    required_permissions:            # resource = a client_id (built-in apps too)
      - { resource: orders-api, type: delegated|application, value: Orders.Read }
directory_roles:
  - { user: a@example.com, role: GlobalAdmin|ApplicationAdmin|UserAdmin }
role_assignments:                    # exactly one of user / group / application
  - { resource: orders-api, role: Orders.Admin, group: Engineers }
admin_consents:                      # tenant-wide consent to required permissions
  - { client: web, resource: orders-api }                    # all of them
  - { client: sync, resource: orders-api, app_roles: [Orders.Sync], scopes: [] }
```

Admin consents follow `POST /api/v1/consents`: both lists left out grant
every required permission of the client on the resource; listed values must
be required ones. Consented app roles become app role assignments of the
client (reconciled together with `role_assignments`). Widening a grant keeps
the tokens issued under it; narrowing revokes the grant (and its refresh
tokens) and grants the new set, like a revoke + grant through the API.
Removing a managed scope drops it from consent grants and revokes the
refresh tokens carrying it (as `DELETE …/scopes/{id}`).

Group members listed in the file become manual, managed members. Removing
one from the file removes the membership — unless an identity provider's
group mapping also keeps it, in which case the row stays as the mapping's
alone (no longer manual or managed). Each write re-checks the row's
`idp_id` rather than trusting what apply read (`DELETE … WHERE idp_id IS
NULL`, else `UPDATE … WHERE idp_id IS NOT NULL`), so a membership a mapping
took over meanwhile is never deleted, and one someone removed meanwhile
(the management API doesn't take apply's lock) is neither reported nor
audited. Likewise a listed member is never taken as present from that
read: adopting one updates only a still-manual row, and anything else goes
through an insert, so a declared membership someone deleted meanwhile is
added back (`+ member`, audited). Deleting a managed identity provider
deletes its linked identities and the memberships only its mappings kept,
like `DELETE /api/v1/identity-providers/{id}`.

### What apply does not do (by design)

- **No secrets in the file.** Application client secrets are never declared:
  create them through the API / admin UI (or use the bootstrap provisioning
  app). Passwords and IdP client secrets come from environment variables
  (`*_env`); a password is used only when the user is created and an IdP
  secret only while the provider has none, so a re-apply never rotates them.
  A `*_env` name must be `OAUTH_APPLY_` followed by `A-Z`, `0-9` or `_`
  (checked before anything is written). Apply runs with the server's own
  secrets in its environment (`OAUTH_MASTER_KEY`, `DATABASE_URL`,
  `SMTP_URL`, `TELEGRAM_BOT_TOKEN`, …); without the prefix whoever writes
  the file could seal one of them as the client secret of an IdP whose
  token endpoint they control. No server variable carries the prefix (a
  unit test keeps it that way), and the CLI reads no other variable for a
  `*_env` reference.
- **No IdP repointing.** Changing an existing provider's `issuer`,
  `client_id` or `discovery_url` unlinks every identity and must drop the
  running servers' discovery caches; apply refuses it — do it through the
  management API or admin UI.
- **No tenant creation or tenant settings** (`oauth bootstrap --tenant` and
  `PATCH /api/v1/settings`), no IdP group mappings, no emails (users created
  by apply get no verification or invitation mail).
