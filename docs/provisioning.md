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
                [--provisioning-app <client_id> [--provisioning-role read|read-write] [--rotate-secret]]
# make bootstrap [TENANT=…] [ADMIN_EMAIL=… [RESET=1]] [PROVISIONING_APP=… [PROVISIONING_ROLE=…] [ROTATE=1]]
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
  with `read` downgrades a `read-write` app, and says so). A client secret (180 days) is issued and printed **once** — when
  the app is created, or again with `--rotate-secret` (older secrets stay
  valid until they expire or are deleted). The app gets a token with
  `client_credentials` and `scope=api://management-api/.default` on the
  tenant's host. Because the app holds management API access only a Global
  Admin can change its credentials or redirect URIs.
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
rolls back, so its output is exactly what an apply would change. Output lines:
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
`managed = true` (shown as *Managed by apply* in the admin UI and as
`managed` in the management API).

**Deletion.** Only managed objects the file no longer declares are deleted;
objects apply never created or adopted are never touched. Lists are the
complete desired set of managed objects: a list left out means "none". So
removing a user from the file deletes that user if apply manages it, and an
empty file (`tenant: contoso`) deletes every managed object of the tenant.

**Scalars.** An optional setting left out keeps the stored value (on create:
the management API's default). `null` clears a nullable one
(`identifier_uri`, `discovery_url`, `mfa_acr`, `hosted_domain`).

**Validation** is the management API's: the same validators and write
helpers (`api::app_body`, `api::validate`, `api::idp_body`,
`api::role_assignments`, …), the same per-app caps, the last-Global-Admin
rule (removing, disabling or deleting the last enabled Global Admin fails;
it is checked on the end state, so one file may promote a new Global Admin
and disable or demote the old one). Disabling a user revokes their sessions
and refresh tokens, like `PATCH /api/v1/users/{id}`.
Apply acts with full trust (like a Global Admin): it may assign management
API roles and change apps that hold them. The schema is strict: unknown
fields, duplicate keys and a role assignment without exactly one principal
are errors before anything is written. So is a reference (group member,
directory role, role assignment, required permission, admin consent) to a
user, group or app that apply manages but the file no longer declares: it
would be created and then deleted with its target in the same run. Files
are limited to 4 MiB.

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
    access_token_format, signing_alg, groups_claim_format, assignment_required,
    access_token_ttl_secs, refresh_token_ttl_secs, device_code_enabled,
    mfa_policy                       # optional, as in the API
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
alone (no longer manual or managed). Deleting a managed identity provider
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
- No back-channel logout settings: the server doesn't support back-channel
  logout yet (`backchannel_logout_supported: false`).
