# Management API (`/api/v1`)

Graph-like REST API for the admin and My Account SPAs (step 5) and for
service apps. JSON in, JSON out. Implemented in `crates/server/src/api/`,
authorization rules in `crates/server/src/authz.rs`. It is served on each
tenant's own host `{origin}` = `{scheme}://{t}.{PUBLIC_URL host}[:port]`:
`{origin}/api/v1/…` is tenant `{t}`'s directory (no tenant in the path).

## Authentication

`Authorization: Bearer <access token>` on every call (no cookies, so no CSRF
surface). On tenant `{t}`'s host the token must be:

- a valid access token **of tenant `{t}`**: a JWT signed by a key `{t}`
  still publishes (issuer `{origin}`), or an active opaque token of
  `{t}` (the management API issues JWTs unless its format is changed);
- with `tid` = the tenant's id;
- for the tenant's built-in **`management-api`** (audience
  `api://management-api`). Tokens for any other resource are rejected;
- delegated (`idtyp: user`): `scp` must contain `Directory.AccessAsUser`
  (bare value, as in every `scp` claim). The user must exist and be enabled
  and the token's session (`sid`) must still exist — checked on every call,
  so disabling a user, signing out (logout, revoked session, sign-out
  everywhere, an admin's password reset) cuts the token off at once, JWT or
  not. Tokens refreshed after the session ended don't work here either — so
  management access also ends when the sign-in session expires
  (`SESSION_TTL_HOURS`, default 24 h), even while the SPA still holds a valid
  refresh token: the SPA must sign the user in again;
- app-only (`idtyp: app`, client credentials with
  `scope=api://management-api/.default`): authorized by the app's
  **current** management-API app role assignments, read on every call —
  not by the token's `roles` claim. Removing the assignment, or deleting the
  app, ends its access at once.

The built-in SPAs get such tokens with
`scope=openid offline_access api://management-api/Directory.AccessAsUser`
(pre-consented). Service apps: a GlobalAdmin assigns the app the
management-API app role `Directory.Read.All` or `Directory.ReadWrite.All`
(`POST role-assignments`), then the app uses client credentials.

`/api/v1/tenants` and `/api/v1/tenants/{slug}` (GET / PATCH) exist only on
the **system tenant's host** (`system.{PUBLIC_URL host}`; 404 on every other
host): the token must be a delegated token **of the `system` tenant** whose
user is a GlobalAdmin there. A tenant's own admins use `/api/v1/settings` on
their host.

`me/…` endpoints accept delegated tokens only.

### Authorization

| Caller | Read (all `GET`s) | Users, groups, members | Applications & co.¹ | Directory roles | Identity providers | Tenants |
|---|---|---|---|---|---|---|
| GlobalAdmin | ✓ | ✓ | ✓ | ✓ | ✓ | system tenant only |
| UserAdmin | ✓ | ✓ | – | – | read | – |
| ApplicationAdmin | ✓ | – | ✓ | – | read | – |
| member without directory role | – | – | – | – | – | – |
| app `Directory.Read.All` | ✓ (not identity providers) | – | – | – | – | – |
| app `Directory.ReadWrite.All` | ✓ (not identity providers) | ✓ | ✓ | – | – | – |

¹ applications, secrets, scopes, app roles, required permissions, app role
assignments, consent grants. Any directory role reads the whole directory
(Entra: directory roles imply directory read); members without one only
reach `me/…`.

Additional rules:

- **Administrator protection:** users holding GlobalAdmin or
  ApplicationAdmin can only be updated, disabled, deleted, password/MFA
  reset or signed out by a GlobalAdmin (403 for UserAdmins and apps).
- **Management API grants** (assigning its app roles, granting / revoking
  consent on it) need a GlobalAdmin: they are directory access.
- **Last GlobalAdmin:** unassigning, disabling or deleting the tenant's last
  enabled GlobalAdmin → 409 (concurrent attempts serialize).
- **Built-in apps** (`management-api`, `admin-portal`, `my-account`): not
  deletable; only a GlobalAdmin may change them, and only `display_name`,
  `access_token_ttl_secs`, `refresh_token_ttl_secs`; no secrets / scopes /
  roles / required permissions may be added or removed (403).
- **Privileged apps' credentials:** an app holding management-API access (an
  app role assignment of, or a consent grant on, the management API) can
  only have its secrets added / deleted and its `redirect_uris` /
  `post_logout_redirect_uris` changed by a GlobalAdmin — otherwise an
  ApplicationAdmin could take over its `Directory.ReadWrite.All` (403).
- **Per-app caps:** 50 secrets, 200 scopes, 200 app roles, 200 required
  permissions (409 beyond). Creates lock the parent app row before
  counting, so concurrent requests can't overshoot a cap.
- **Audit retention:** `audit_retention_days` is 30–3650 for everyone: a
  tenant admin can't erase recent history by shrinking it.

## Conventions

- **Errors:** `{ "error": "<code>", "error_description": "<text>" }`.

  | Status | `error` | When |
  |---|---|---|
  | 400 | `invalid_request` | malformed JSON / query, unknown body field, validation failure, an object named in the **body** doesn't exist |
  | 401 | `invalid_token` | missing / invalid / expired / revoked token, other tenant, other audience (`WWW-Authenticate: Bearer error="invalid_token"`) |
  | 403 | `forbidden` | authenticated but not allowed (role, scope, protected target, built-in app, wrong current password) |
  | 404 | `not_found` | unknown or disabled tenant, unknown object in the **path** (also malformed ids). Objects of other tenants are always 404 — never 403 |
  | 409 | `conflict` | duplicate (email, slug, client_id, identifier_uri, scope/role value, membership, assignment), last GlobalAdmin, per-app caps, state conflicts |
  | 429 | `rate_limited` | password / code re-verification over the per-account limit (`Retry-After`) |
- **Timestamps** are RFC 3339 UTC with milliseconds (`2026-10-13T10:00:00.000Z`).
- **Ids** are UUIDs. Bodies reject unknown fields.
- **Pagination** (lists marked *paged*): `?limit=` (1–200, default 50) and
  `?cursor=` (opaque; pass `next_cursor` of the previous page). Response
  `{ "items": [...], "next_cursor": "…" | null }`. Ordered by creation
  (oldest first) except the audit log (newest first). Unpaged lists return
  `{ "items": [...] }`.
- **Search** (`?search=`): case-insensitive substring, literal (no
  wildcards), ≤ 256 characters. Implemented as `ILIKE '%…%'` without a
  trigram index: a sequential scan per tenant, fine for directories of
  thousands of objects; add `pg_trgm` indexes before it isn't.
- `PATCH` with nothing to change returns the object unchanged (no audit
  event); audit `fields` list only values that actually changed.
- `POST` creating an object → `201` with the object; `PATCH` → `200` with
  the object; `DELETE` and actions without a result → `204`.
- Every successful mutation writes an audit event in the same transaction.

## Objects

```jsonc
// Tenant
{ "id", "slug", "display_name", "is_system": false, "disabled": false,
  "audit_retention_days": 90, "created_at", "updated_at" }
// User (list / create / update)
{ "id", "email", "display_name", "user_type": "member", "email_verified": false,
  "disabled": false, "must_change_password": true, "has_password": true,
  "created_at", "updated_at" }
// UserDetail (GET users/{id}, GET me) = User +
{ "directory_roles": ["GlobalAdmin"],
  "mfa": { "totp": false, "totp_pending": false, "recovery_codes_remaining": 0, "passkeys": 0, "telegram": false } }
// … and on GET users/{id} only:
{ "identities": [Identity] }
// Identity (linked upstream identity; `subject` for admins only)
{ "id", "idp_id", "idp_name", "subject", "email": null, "linked_at", "last_used_at": null }
// IdentityProvider (the client secret is write-only: only `has_secret`)
{ "id", "name", "kind": "oidc", "enabled": true, "visible": true, "issuer",
  "discovery_url": null, "client_id", "has_secret": true, "client_auth": "post|basic",
  "scopes": ["openid","email","profile"], "policy": "jit|link_only|deny",
  "trust_upstream_mfa": false, "mfa_acr": null, "email_domains": [],
  "redirect_uri": "{origin}/federation/callback", "created_at", "updated_at" }
// … plus on create / GET / PATCH: { "users_only_via": 0, "linked_users": 0 }
// Session
{ "id", "amr": ["pwd"], "auth_time", "ip", "user_agent", "created_at", "expires_at",
  "current": false }   // `current`: the session the calling token came from (me only)
// Group
{ "id", "display_name", "description": null, "created_at", "updated_at" }
// DirectoryRoleAssignment
{ "id", "user_id", "role": "GlobalAdmin|ApplicationAdmin|UserAdmin", "created_at" }
// Application
{ "id", "client_id", "display_name", "client_type": "confidential|public", "builtin": false,
  "redirect_uris": [], "post_logout_redirect_uris": [], "identifier_uri": null,
  "audience": "api://<client_id>",          // identifier_uri, else api://{client_id}
  "access_token_format": "jwt|opaque", "signing_alg": "RS256|ES256",
  "access_token_ttl_secs": 3600, "refresh_token_ttl_secs": 1209600,
  "created_at", "updated_at" }
// ClientSecret (the value only in the create response, as "secret")
{ "id", "hint": "abc", "description": null, "expires_at", "created_at" }
// Scope
{ "id", "value", "description", "admin_consent_required": false, "created_at" }
// AppRole
{ "id", "value", "display_name", "description", "allowed_member_types": ["user","application"], "created_at" }
// RequiredPermission
{ "id", "resource_application_id", "resource_client_id", "type": "delegated|application",
  "permission_id", "value", "created_at" }
// AppRoleAssignment
{ "id", "resource_application_id", "app_role_id",
  "principal_type": "user|group|application", "principal_id", "created_at" }
// ConsentGrant (user_id null = tenant-wide admin consent)
{ "id", "client_application_id", "resource_application_id", "user_id": null,
  "scopes": ["Orders.Read"], "created_at", "updated_at" }
// AuditEvent
{ "id", "at", "actor_type": "user|application|system", "actor_id": null,
  "event_type": "user.create", "target_type": "user", "target_id",
  "outcome": "success|failure", "ip": "203.0.113.7", "details": {} }
```

## Tenants (system GlobalAdmin, system host only)

| Method & path | Body | Response |
|---|---|---|
| `GET /api/v1/tenants` *paged* `?search=` (slug, name) | – | `Tenant`s |
| `POST /api/v1/tenants` | `{ slug, display_name, admin_email, admin_display_name? }` | 201 `{ tenant, admin: { id, email }, one_time_password }` |
| `GET /api/v1/tenants/{slug}` | – | `Tenant` (also disabled ones) |
| `PATCH /api/v1/tenants/{slug}` | `{ display_name?, disabled?, audit_retention_days? (30–3650) }` | `Tenant` |

Create provisions keys, built-in apps and the first GlobalAdmin (password
must be changed at first sign-in) in one transaction; slug rules as in
`directory::slug` (a DNS label: no trailing `-`, no `--` as characters 3–4
like punycode `xn--`; reserved service names like `www`, `mail`, `api` → 400; taken → 409).
The new tenant lives at `{scheme}://{slug}.{PUBLIC_URL host}[:port]`. Disabling makes the
tenant 404 everywhere (sign-in, tokens, API); the system tenant can't be
disabled (403). A disabled tenant whose slug fails today's rules (created
before they existed, e.g. `www`) can't be re-enabled (`disabled: false` →
400): the server refuses to start with such a tenant enabled.

## Tenant settings — read: any role, `Read.All`; write: the tenant's GlobalAdmin (delegated)

| Method & path | Body | Response |
|---|---|---|
| `GET /api/v1/settings` | – | `Tenant` |
| `PATCH /api/v1/settings` | `{ display_name?, audit_retention_days? (30–3650) }` | `Tenant` (audited as `tenant.update` in the tenant's own log) |

Creating, disabling and enabling tenants stay with the system tenant's
GlobalAdmins (`disabled` here → 400, unknown field).

## Users — read: any role; write: GlobalAdmin, UserAdmin, `ReadWrite.All`

| Method & path | Body | Response |
|---|---|---|
| `GET users` *paged* `?search=` (email, name) | – | `User`s |
| `POST users` | `{ email, display_name, password?, must_change_password? (default true), invite? }` | 201 `{ user, one_time_password, invite_sent }` — password generated (24 chars, must change) when `password` is omitted, else `null`. `invite: true` (only with email configured, else 400; not with `password` / `must_change_password`): no password, a 7-day invitation link is mailed instead. With email configured a non-invited user gets a verification link |
| `GET users/{id}` | – | `UserDetail` |
| `PATCH users/{id}` | `{ display_name?, email?, disabled? }` | `User` (409 if the email is taken). A new email resets `email_verified`, voids links sent to the old address, mails a verification link — or, for a user without a password, a new invitation — (email configured) and notifies the old address if it was verified |
| `POST users/{id}/invite` | – | 204: re-sends the invitation, the older link stops working (409 if the user has a password, a passkey or a linked identity, 400 email not configured) |
| `DELETE users/{id}` | – | 204 (sessions, tokens, memberships, roles, grants cascade) |
| `POST users/{id}/reset-password` | `{ password?, must_change_password? (default true) }` (send `{}` to generate) | `{ one_time_password, must_change_password }` |
| `POST users/{id}/reset-mfa` | – | 204: TOTP, recovery codes and passkeys deleted, Telegram unlinked (audit details `passkeys_removed`, `telegram_unlinked`). 409 for a user with passkeys but neither a password nor a linked identity (it would lock them out): `reset-password` first |
| `GET users/{id}/passkeys` | – | `{ items: Passkey[] }` (see [me.md](me.md)) |
| `DELETE users/{id}/passkeys/{passkey_id}` | – | 204; 409 when it is the user's last sign-in method (password, passkeys, linked identities) |
| `DELETE users/{id}/identities/{identity_id}` | – | 204: the upstream identity is unlinked (audit `user.identity_unlink`, `via: admin`); 409 when it is the user's last sign-in method |
| `GET users/{id}/sessions` | – | `{ items: Session[] }` (unexpired) |
| `POST users/{id}/revoke-sessions` | – | 204: sessions deleted, refresh + opaque access tokens revoked |

Paths are relative to `{origin}/api/v1/`. Password rules: 12–256
characters. A password reset and disabling a user also end all their
sessions and revoke refresh / opaque access tokens (JWTs expire).

## Groups — read: any role; write: GlobalAdmin, UserAdmin, `ReadWrite.All`

| Method & path | Body | Response |
|---|---|---|
| `GET groups` *paged* `?search=` | – | `Group`s |
| `POST groups` | `{ display_name, description? }` | 201 `Group` |
| `GET groups/{id}` · `PATCH groups/{id}` · `DELETE groups/{id}` | `{ display_name?, description? }` | `Group` / 204 |
| `GET groups/{id}/members` *paged* | – | `User`s |
| `POST groups/{id}/members` | `{ user_id }` | 204 (409 if already a member) |
| `DELETE groups/{id}/members/{user_id}` | – | 204 |

## Directory roles — read: any role; write: GlobalAdmin (delegated) only

| Method & path | Body | Response |
|---|---|---|
| `GET directory-roles` *paged* `?user_id=&role=` | – | `DirectoryRoleAssignment`s |
| `POST directory-roles` | `{ user_id, role }` | 201 `DirectoryRoleAssignment` |
| `DELETE directory-roles/{id}` | – | 204 (409 for the last enabled GlobalAdmin) |

## Applications — read: any role; write: GlobalAdmin, ApplicationAdmin, `ReadWrite.All`

| Method & path | Body | Response |
|---|---|---|
| `GET applications` *paged* `?search=` (name, client_id) | – | `Application`s |
| `POST applications` | `{ display_name, client_id?, client_type? (confidential), redirect_uris?, post_logout_redirect_uris?, identifier_uri?, access_token_format?, signing_alg?, access_token_ttl_secs?, refresh_token_ttl_secs? }` | 201 `Application` |
| `GET applications/{id}` | – | `Application` |
| `PATCH applications/{id}` | same fields except `client_id`, `client_type` (immutable → 400); `identifier_uri: null` clears it | `Application` |
| `DELETE applications/{id}` | – | 204 (everything of the app cascades) |

Validation:

- `client_id`: 1–128 of `A-Z a-z 0-9 . _ -`, starting alphanumeric;
  default: a random UUID. Unique per tenant (409).
- `redirect_uris`, `post_logout_redirect_uris` (≤ 32 each, no
  duplicates): absolute `https://` URI with a host (lowercase scheme), or
  `http://127.0.0.1…` / `http://[::1]…` (loopback; registered without a
  port, any port matches). No fragment, no userinfo, no whitespace,
  ≤ 2048 characters. `http://localhost` is rejected (may resolve off-host).
- `identifier_uri`: `api://{own client_id}` (lowercase scheme, nothing
  else after `api://`), or an `https://` URI without query / fragment; scope
  token characters only, no trailing `/`, ≤ 256; unique per tenant (409).
- `access_token_format` `jwt|opaque`, `signing_alg` `RS256|ES256`,
  `access_token_ttl_secs` 300–86400, `refresh_token_ttl_secs` 1 – 90 days
  (7 776 000) for confidential and 1 – 7 days (604 800) for public clients
  (new public clients default to 24 h; the DB also caps at 90 days). The
  access token format, alg and TTL apply to tokens **for** this app as a
  resource; `signing_alg` also signs ID tokens issued **to** it.

### Secrets

| Method & path | Body | Response |
|---|---|---|
| `GET applications/{id}/secrets` | – | `{ items: ClientSecret[] }` (never values) |
| `POST applications/{id}/secrets` | `{ description?, expires_in_days? (1–730, default 180) }` | 201 `ClientSecret` + `"secret"`: the value, shown only now |
| `DELETE applications/{id}/secrets/{secret_id}` | – | 204 |

Public clients can't have secrets (400).

### Exposed scopes and app roles

| Method & path | Body | Response |
|---|---|---|
| `GET applications/{id}/scopes` | – | `{ items: Scope[] }` |
| `POST applications/{id}/scopes` | `{ value, description?, admin_consent_required? (false) }` | 201 `Scope` |
| `PATCH applications/{id}/scopes/{scope_id}` | `{ description?, admin_consent_required? }` | `Scope` |
| `DELETE applications/{id}/scopes/{scope_id}` | – | 204; the value is also removed from consent grants, required permissions naming it cascade, and refresh-token families whose grant held it are revoked (with their opaque access tokens). Refresh never re-mints a scope the resource no longer exposes |
| `GET applications/{id}/roles` | – | `{ items: AppRole[] }` |
| `POST applications/{id}/roles` | `{ value, display_name, description?, allowed_member_types }` | 201 `AppRole` |
| `PATCH applications/{id}/roles/{role_id}` | `{ display_name?, description?, allowed_member_types? }` | `AppRole` |
| `DELETE applications/{id}/roles/{role_id}` | – | 204 (assignments cascade) |

`value`: 1–120 printable ASCII without space, `"`, `\` or `/`; unique per
app (409); immutable (`value` in PATCH → 400). Scope values must not be
`openid`, `profile`, `email`, `offline_access` or `.default` in any case
(400). `allowed_member_types` is a non-empty set ⊆ {`user`, `application`}:
duplicates collapse and it is stored and returned in canonical order
(`["user","application"]`), so a reordered PATCH is no change.

### Required permissions

| Method & path | Body | Response |
|---|---|---|
| `GET applications/{id}/required-permissions` | – | `{ items: RequiredPermission[] }` |
| `POST applications/{id}/required-permissions` | `{ resource_application_id, type: "delegated"\|"application", value }` | 201 `RequiredPermission` (400 if the resource doesn't expose `value`) |
| `DELETE applications/{id}/required-permissions/{permission_id}` | – | 204 |

## App role assignments — read: any role; write: GlobalAdmin, ApplicationAdmin, `ReadWrite.All`

| Method & path | Body | Response |
|---|---|---|
| `GET role-assignments` *paged* `?resource_application_id=&app_role_id=&principal_id=` | – | `AppRoleAssignment`s |
| `POST role-assignments` | `{ app_role_id, principal_type: "user"\|"group"\|"application", principal_id }` | 201 `AppRoleAssignment` |
| `DELETE role-assignments/{id}` | – | 204 |

The role's `allowed_member_types` must include `user` (users, groups) or
`application` (client apps), else 400. User / group assignments become
`roles` in delegated tokens for the resource, application assignments
`roles` in client-credentials tokens. Management-API roles: GlobalAdmin only.

## Consents — read: any role; write: GlobalAdmin, ApplicationAdmin, `ReadWrite.All`

| Method & path | Body | Response |
|---|---|---|
| `GET consents` *paged* `?client_application_id=&resource_application_id=&user_id=` | – | `ConsentGrant`s |
| `POST consents` | `{ client_application_id, resource_application_id, scopes?, app_roles? }` | 200 `{ grant: ConsentGrant\|null, role_assignments: AppRoleAssignment[] }` |
| `DELETE consents/{id}` | – | 204 |

`POST` = "Grant admin consent": every value must be a **required
permission** of the client on that resource (400 otherwise). Without
`scopes` and `app_roles` everything required is granted. Delegated scopes
merge into the tenant-wide admin grant (`user_id: null`); application
permissions become app role assignments to the client (idempotent).
Consent on the management API: GlobalAdmin only.

`DELETE` removes the grant (user or admin) and revokes what the client got
under it: all refresh-token families and opaque access tokens of
(client, resource) — for the grant's user, or for **every** user when it is
the admin grant (their tokens may rest on it). JWT access tokens can't be
recalled and expire. App role assignments made by a consent are removed via
`DELETE role-assignments/{id}`.

## Identity providers — read: any directory role; write: GlobalAdmin (delegated) only; apps: none

`identity-providers[/{id}]`: contract in [identity_providers.md](identity_providers.md).

## Audit events — read: any role, `Read.All`

`GET audit-events` *paged, newest first*
`?event_type=&actor_id=&target_id=&from=&to=` (`from` inclusive, `to`
exclusive, RFC 3339) → `AuditEvent`s.

| `event_type` | Actor → target | Details |
|---|---|---|
| `sign_in` | user (`actor_id` null for an unknown account) → user | success: `session_id`, `application_id`, `amr`; failure: `reason` (`invalid_password`, `unknown_account`, `disabled`, `mfa_failed` + `factor`; passkeys: `factor: "passkey"` + the verifier's reason, e.g. `invalid_challenge`, `foreign_credential`, `sign_count_regression`; federation: `factor: "federation"`, `idp_id` + the reason, e.g. `id_token_nonce`, `token_refused`, `unknown_kid`, `upstream_error`, `account_exists`, `not_linked`) |
| `token.refresh_reuse`, `token.code_replay` | client app → user, failure | `family_id` / `authorization_code_id` |
| `tenant.create`, `tenant.update` | system admin → tenant (logged in the system tenant; a system admin's `tenant.update` of another tenant is ALSO logged in that tenant's own log, in the same transaction; a tenant admin's settings change only in their own) | `slug`, `admin_user_id` / `fields`, `disabled` |
| `user.create`, `user.update`, `user.delete`, `user.password_reset`, `user.mfa_reset`, `user.sessions_revoke` | admin or app → user (JIT federation: user → self) | create: `email`, `password` (`generated` / `set_by_admin`), JIT: `via: "federation"`, `idp_id`; update: `fields`, `disabled`; delete: `email`; reset: `must_change_password`, `generated`; mfa reset: `passkeys_removed` |
| `user.mfa.passkey_register`, `user.mfa.passkey_rename`, `user.mfa.passkey_remove` | user → self (invite: by the link's user), admin → user (remove) | `passkey_id`, `name`, `via` (`me` / `admin` / `invite`) |
| `user.mfa.passkey_sign_count_regression` | user → self (failure) | `via: "reauth"` |
| `user.password_change` | user → self | `via`: `sign_in` (forced change) / `me` |
| `user.profile_update`, `user.session_revoke`, `user.mfa.totp_enroll`, `user.mfa.totp_remove`, `user.mfa.recovery_codes_regenerate` | user → self | `fields` / `session_id` |
| `user.invite` | admin → user | `email`, `resend` |
| `user.identity_link`, `user.identity_unlink` | user → self, admin → user (unlink) | `idp_id`, `via` (`sign_in` / `me` / `admin`), `identity_id`; failures (outcome `failure`) carry `reason` — a My Account link that didn't complete, or a link skipped when a sign-in completed (`via: sign_in`, `reason` `link_unavailable` / `already_linked`) |
| `identity_provider.create`, `identity_provider.update`, `identity_provider.delete` | GlobalAdmin → identity provider | `name`, `issuer`, `policy` / `fields`, `identities_removed` / `users_only_via` |
| `user.email_verify_request`, `user.email_verify`, `user.email_change_request`, `user.email_change_complete`, `user.password_reset_request`, `user.password_reset_complete`, `user.invite_accept`, `user.notification_prefs_update` | user → self (link redemptions: by the link's user, with the caller's IP) | `email` / `new_email` / `events` |
| `group.create`, `group.update`, `group.delete`, `group.member_add`, `group.member_remove` | → group | `display_name`, `fields`, `user_id` |
| `directory_role.assign`, `directory_role.unassign` | → user | `role`, `assignment_id` |
| `application.create`, `application.update`, `application.delete`, `application.secret_add`, `application.secret_remove`, `application.scope_add`, `application.scope_update`, `application.scope_remove`, `application.role_add`, `application.role_update`, `application.role_remove`, `application.permission_add`, `application.permission_remove` | → application | `client_id`, `fields`, `secret_id`, `scope_id`/`role_id` + `value`, `permission_id` |
| `app_role_assignment.create`, `app_role_assignment.delete` | → assignment | create: `resource_client_id`, `role`, `principal_type`, `principal_id`; delete: `resource_client_id`, `app_role_id` |
| `consent.grant`, `consent.revoke` | → consent grant (or client app) | `client_id`, `resource_client_id`, `scopes`, `app_roles`, `user_id` |

Details never contain passwords, secrets, codes or tokens. Rate-limited
sign-in attempts are not logged (they cost an attacker nothing). Events are
deleted after the tenant's `audit_retention_days` (default 90) by the
sweeper job.

## Me

`/api/v1/me…` (self-service, any user's delegated token): see [me.md](me.md).
