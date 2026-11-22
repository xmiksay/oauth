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

`/api/v1/tenants`, `/api/v1/tenants/{slug}` (GET / PATCH) and
`/api/v1/tenants/{slug}/users[/…]` exist only on
the **system tenant's host** (`{SYSTEM_TENANT_SLUG}.{PUBLIC_URL host}`, default
`system.…`; 404 on every other host): the token must be a delegated token **of
the system tenant** whose
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
  only have its secrets added / deleted, its `redirect_uris` /
  `post_logout_redirect_uris` / `web_origins` / `backchannel_logout_uri`
  changed and `device_code_enabled` toggled by a GlobalAdmin — otherwise an
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
  | 413 | `payload_too_large` | request body over the size limit (2 MiB) |
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
{ "id", "slug", "origin": "https://{slug}.{PUBLIC_URL host}", // the apex origin for the APEX_TENANT
  "display_name", "is_system": false, "disabled": false,
  "audit_retention_days": 90, "mfa_policy": "optional|required",
  "logout_revokes_refresh_tokens": true, "allow_non_expiring_secrets": false,
  "created_at", "updated_at" }
// User (list / create / update)
{ "id", "email", "display_name", "user_type": "member", "email_verified": false,
  "disabled": false, "must_change_password": true, "has_password": true,
  "managed": false,                         // read-only, see below
  "created_at", "updated_at" }
// UserDetail (GET users/{id}, GET me) = User +
{ "directory_roles": ["GlobalAdmin"],
  "mfa": { "totp": false, "totp_pending": false, "recovery_codes_remaining": 0, "passkeys": 0, "telegram": false } }
// … and on GET users/{id} only:
{ "identities": [Identity] }
// Identity (linked upstream identity; `subject` for admins only)
{ "id", "idp_id", "idp_name", "subject", "email": null, "linked_at", "last_used_at": null }
// IdentityProvider: shape in identity_providers.md
// Session
{ "id", "amr": ["pwd"], "auth_time", "ip", "user_agent", "created_at", "expires_at",
  "current": false }   // `current`: the session the calling token came from (me only)
// Group
{ "id", "display_name", "description": null, "managed": false, "created_at", "updated_at" }
// DirectoryRoleAssignment
{ "id", "user_id", "role": "GlobalAdmin|ApplicationAdmin|UserAdmin", "managed": false, "created_at" }
// Application
{ "id", "client_id", "display_name", "client_type": "confidential|public", "builtin": false,
  "managed": false,
  "redirect_uris": [], "post_logout_redirect_uris": [], "identifier_uri": null,
  "web_origins": [],                        // explicit CORS origins
  "effective_web_origins": [],              // read-only: web_origins ∪ (public clients) redirect-URI origins
  "audience": "api://<client_id>",          // identifier_uri, else api://{client_id}
  "access_token_format": "jwt|opaque", "signing_alg": "RS256|ES256",
  "groups_claim_format": "id|name",         // what the groups claim of tokens for this resource (and of its ID tokens) carries
  "id_token_groups": "none|all|assigned",   // groups in ID tokens / userinfo issued to it
  "assignment_required": false,             // only principals holding one of its roles get tokens
  "access_token_ttl_secs": 3600, "refresh_token_ttl_secs": 1209600,
  "device_code_enabled": false,             // RFC 8628 device code grant opt-in
  "mfa_policy": "inherit|required",         // required: sign-ins to it (client or resource) need MFA
  "backchannel_logout_uri": null,           // OIDC Back-Channel Logout endpoint (https)
  "backchannel_logout_session_required": false,
  "created_at", "updated_at" }
// ClientSecret (the value only in the create response, as "secret")
{ "id", "hint": "abc", "description": null, "expires_at": null, "never_expires": true, "created_at" }
// Scope
{ "id", "value", "description", "admin_consent_required": false, "managed": false, "created_at" }
// AppRole
{ "id", "value", "display_name", "description", "allowed_member_types": ["user","application"],
  "managed": false, "created_at" }
// RequiredPermission
{ "id", "resource_application_id", "resource_client_id", "type": "delegated|application",
  "permission_id", "value", "managed": false, "created_at" }
// AppRoleAssignment
{ "id", "resource_application_id", "app_role_id",
  "principal_type": "user|group|application", "principal_id", "managed": false, "created_at" }
// ConsentGrant (user_id null = tenant-wide admin consent)
{ "id", "client_application_id", "resource_application_id", "user_id": null,
  "scopes": ["Orders.Read"], "managed": false, "created_at", "updated_at" }
// AuditEvent
{ "id", "at", "actor_type": "user|application|system|apply", "actor_id": null,
  "event_type": "user.create", "target_type": "user", "target_id",
  "outcome": "success|failure", "ip": "203.0.113.7", "details": {} }
```

`managed` (read-only) marks objects created or adopted by `oauth apply`
from a tenant file ([provisioning](../provisioning.md)) — every shape above
that lists it, and identity providers; group memberships carry it only
internally (a member item's `managed` is the user's): the next apply
overwrites what the file declares and deletes them once the file no longer
does. The API changes them like any other object. Events written by apply
have `actor_type: apply` (no `actor_id`); those of `oauth bootstrap`,
`system`.

## Tenants (system GlobalAdmin, system host only)

| Method & path | Body | Response |
|---|---|---|
| `GET /api/v1/tenants` *paged* `?search=` (slug, name) | – | `Tenant`s |
| `POST /api/v1/tenants` | `{ slug, display_name, admin_email, admin_display_name? }` | 201 `{ tenant, admin: { id, email }, one_time_password }` |
| `GET /api/v1/tenants/{slug}` | – | `Tenant` (also disabled ones) |
| `PATCH /api/v1/tenants/{slug}` | `{ display_name?, disabled?, audit_retention_days? (30–3650), mfa_policy? (optional\|required), logout_revokes_refresh_tokens?, allow_non_expiring_secrets? }` | `Tenant` |
| `GET /api/v1/tenants/{slug}/users` *paged* `?search=` (email, name) | – | that tenant's `User`s |
| `GET /api/v1/tenants/{slug}/users/{id}` | – | `UserDetail` (as `GET users/{id}`) |
| `POST /api/v1/tenants/{slug}/users/{id}/reset-password` | optional: empty, or a JSON object with no fields (`{}`), read as JSON whatever the `Content-Type`; any field or non-object / malformed body → 400 (the password is always generated; the error never quotes the body, not even a field name); over the body limit → 413 | `{ one_time_password, must_change_password: true }` — as `reset-password` without `password`: sessions, refresh tokens and opaque access tokens revoked, the user notified ("reset by a system administrator") |
| `POST /api/v1/tenants/{slug}/users/{id}/reset-mfa` | – | 204 — as `users/{id}/reset-mfa` (notice: "second factors removed by a system administrator"), same 409 for a passkey-only user (reset the password first) |

Create provisions keys, built-in apps and the first GlobalAdmin (password
must be changed at first sign-in) in one transaction; slug rules as in
`directory::slug` (a DNS label: no trailing `-`, no `--` as characters 3–4
like punycode `xn--`; reserved service names like `www`, `mail`, `api`, `system`,
the configured `SYSTEM_TENANT_SLUG` and every slug the system tenant was
renamed away from ([../deploy.md](../deploy.md#system-tenant-slug)) → 400; taken → 409).
The new tenant lives at `{scheme}://{slug}.{PUBLIC_URL host}[:port]`. Disabling makes the
tenant 404 everywhere (sign-in, tokens, API); the system tenant and the
`APEX_TENANT` ([../deploy.md](../deploy.md#apex-tenant)) can't be disabled
(403). `origin` is the tenant's origin and issuer, which for the `APEX_TENANT`
is the apex (`PUBLIC_URL`); clients link to tenants by it. A disabled tenant whose slug fails today's rules (created
before they existed, e.g. `www`) or is a slug the system tenant was renamed away from can't be
re-enabled (`disabled: false` → 400): the server refuses to start with such a tenant enabled.

`/api/v1/tenants/{slug}/users` lets a system GlobalAdmin help a locked-out
user (typically a tenant's own GlobalAdmin) of another tenant: unknown slug →
404; the system tenant's slug → 400 (use its own `users`); disabled tenants
are allowed; a user id not in that tenant → 404. The tenant's administrator
protection doesn't apply (the system GlobalAdmin outranks every tenant role)
and nothing beyond the bearer token is asked for. Each reset is audited
twice in its transaction, both times with the system admin as actor
(`actor_type: user`, `actor_id` = their id, as for tenant updates): in the
system tenant's log with `tenant_id`, `tenant_slug` and the user's `email`
added to the usual details (that log can't resolve another tenant's user
id), and in the target tenant's log with the user's `email` and
`via: "system_admin"` added (the row itself names that tenant).

## Tenant settings — read: any role, `Read.All`; write: the tenant's GlobalAdmin (delegated)

| Method & path | Body | Response |
|---|---|---|
| `GET /api/v1/settings` | – | `Tenant` |
| `PATCH /api/v1/settings` | `{ display_name?, audit_retention_days? (30–3650), mfa_policy? (optional\|required), logout_revokes_refresh_tokens? (RP-initiated logout revokes the session's refresh tokens; default true), allow_non_expiring_secrets? (app admins may create client secrets without expiry; default false) }` | `Tenant` (audited as `tenant.update` in the tenant's own log) |

Creating, disabling and enabling tenants stay with the system tenant's
GlobalAdmins (`disabled` here → 400, unknown field).

## Users — read: any role; write: GlobalAdmin, UserAdmin, `ReadWrite.All`

| Method & path | Body | Response |
|---|---|---|
| `GET users` *paged* `?search=` (email, name) | – | `User`s |
| `POST users` | `{ email, display_name, password?, must_change_password? (default true), invite?, email_verified? (default false) }` | 201 `{ user, one_time_password, invite_sent }` — password generated (24 chars, must change) when `password` is omitted, else `null`. `invite: true` (only with email configured, else 400; not with `password` / `must_change_password`): no password, a 7-day invitation link is mailed instead. With email configured a non-invited user gets a verification link, unless `email_verified: true` (the admin vouches for the address — e.g. no SMTP, or relying parties that require `email_verified`) |
| `GET users/{id}` | – | `UserDetail` |
| `PATCH users/{id}` | `{ display_name?, email?, disabled?, email_verified? }` | `User` (409 if the email is taken). `email_verified` (`true` or `false`) sets the flag directly; needs Directory write and rank over the user like any other edit. A new email resets `email_verified` unless the same request switches it to `true` from a stored `false` (then no verification link is mailed); a value equal to the stored one is an echo and changes nothing, so `{ email: new, email_verified: true }` for an already verified user still resets it (vouching for the new address takes a second PATCH `{ email_verified: true }`). A new email also voids links sent to the old address, mails a verification link — or, for a user without a password, a new invitation — (email configured) and notifies the old address if it was verified. The audit event's `fields` lists `email_verified` only for an explicit switch |
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

`display_name` is unique per tenant, case-insensitively (`Ops` and `ops`
collide; renaming a group to its own name in another case is fine), since it
can be the `groups` claim (`groups_claim_format`).

| Method & path | Body | Response |
|---|---|---|
| `GET groups` *paged* `?search=` | – | `Group`s |
| `POST groups` | `{ display_name, description? }` | 201 `Group` (409 if the name is taken) |
| `GET groups/{id}` · `PATCH groups/{id}` · `DELETE groups/{id}` | `{ display_name?, description? }` | `Group` / 204 (409 if the new name is taken) |
| `GET groups/{id}/members` *paged* | – | `User`s, each with the membership's source: `manual` (an administrator added it) and `idp_id` (kept by that identity provider's group mappings, else `null`; a manual membership a mapping also grants carries both; a mapped membership removed by hand comes back at the user's next sign-in) |
| `POST groups/{id}/members` | `{ user_id }` | 204 (409 if already a member; a membership only a federation group mapping kept becomes manual as well, so it stays when the mapping lets go) |
| `DELETE groups/{id}/members/{user_id}` | – | 204 (also a mapped membership; a mapping adds it again at the user's next sign-in while the claim value is there) |

## Directory roles — read: any role; write: GlobalAdmin (delegated) only

| Method & path | Body | Response |
|---|---|---|
| `GET directory-roles` *paged* `?user_id=&role=` | – | `DirectoryRoleAssignment`s |
| `POST directory-roles` | `{ user_id, role }` | 201 `DirectoryRoleAssignment` |
| `DELETE directory-roles/{id}` | – | 204 (409 for the last enabled GlobalAdmin) |

## Applications — read: any role; write: GlobalAdmin, ApplicationAdmin, `ReadWrite.All`

`applications[/{id}]` with its secrets, exposed scopes / app roles and required permissions:
contract in [applications.md](applications.md).

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
the admin grant (their tokens may rest on it). Refresh tokens of other
resources survive, but can no longer be redeemed for this one
(multi-resource refresh checks consent on every redemption). JWT access
tokens can't be recalled and expire. App role assignments made by a consent are removed via
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
| `tenant.rename` | system (`actor_id` null) → the system tenant, in its own log: `oauth serve` startup (`via: "startup"`) or `oauth bootstrap` (`via: "bootstrap"`) renamed it to a changed `SYSTEM_TENANT_SLUG` with `SYSTEM_TENANT_RENAME=1`; `from` stays reserved ([../deploy.md](../deploy.md#system-tenant-slug)) | `from`, `to`, `via` (`"startup"` / `"bootstrap"`) |
| `tenant.create`, `tenant.update` | system admin → tenant (logged in the system tenant; a system admin's `tenant.update` of another tenant is ALSO logged in that tenant's own log, in the same transaction; a tenant admin's settings change only in their own) | `slug`, `admin_user_id` / `fields`, `disabled` |
| `user.create`, `user.update`, `user.delete`, `user.password_reset`, `user.mfa_reset`, `user.sessions_revoke` | admin or app → user (JIT federation: user → self; a system admin's reset in another tenant: system admin → user in both the system log and the tenant's, see Tenants) | create: `email`, `password` (`generated` / `set_by_admin` / `invite`), `email_verified`, JIT: `via: "federation"`, `idp_id`; update: `fields` (names only, e.g. `email_verified`), `disabled`; delete: `email`; reset: `must_change_password`, `generated`; mfa reset: `passkeys_removed`, `telegram_unlinked`; by a system admin also `email`, plus `tenant_id`, `tenant_slug` in the system log and `via: "system_admin"` in the tenant's |
| `user.mfa.passkey_register`, `user.mfa.passkey_rename`, `user.mfa.passkey_remove` | user → self (invite: by the link's user), admin → user (remove) | `passkey_id`, `name`, `via` (`me` / `admin` / `invite` / `sign_in` — forced enrolment) |
| `user.mfa.passkey_sign_count_regression` | user → self (failure) | `via: "reauth"` |
| `user.password_change` | user → self | `via`: `sign_in` (forced change) / `me` |
| `user.profile_update`, `user.session_revoke`, `user.mfa.totp_enroll`, `user.mfa.totp_remove`, `user.mfa.recovery_codes_regenerate` | user → self | `fields` / `session_id`; `totp_enroll` during a sign-in's forced enrolment: `via: "sign_in"` |
| `user.invite` | admin → user | `email`, `resend` |
| `user.identity_link`, `user.identity_unlink` | user → self, admin → user (unlink) | `idp_id`, `via` (`sign_in` / `me` / `admin`), `identity_id`, unlink: `memberships_removed` (group mappings); failures (outcome `failure`) carry `reason` — a My Account link that didn't complete, or a link skipped when a sign-in completed (`via: sign_in`, `reason` `link_unavailable` / `already_linked`) |
| `identity_provider.create`, `identity_provider.update`, `identity_provider.delete` | GlobalAdmin → identity provider | `name`, `issuer`, `policy` / `fields`, `identities_removed`, `memberships_removed` / `users_only_via`, `memberships_removed` |
| `identity_provider.group_mapping_add`, `identity_provider.group_mapping_remove` | GlobalAdmin → identity provider | `mapping_id`, `claim`, `value`, `group_id`, `group_display_name` (add) / `memberships_removed` (remove) |
| `user.email_verify_request`, `user.email_verify`, `user.email_change_request`, `user.email_change_complete`, `user.password_reset_request`, `user.password_reset_complete`, `user.invite_accept`, `user.notification_prefs_update` | user → self (link redemptions: by the link's user, with the caller's IP) | `email` / `new_email` / `events` |
| `group.create`, `group.update`, `group.delete`, `group.member_add`, `group.member_remove` | → group (a federation group mapping on sign-in: user → group; a repoint, IdP / mapping delete or unlink dropping mapped memberships: admin / user → group) | `display_name`, `fields`, `user_id`; by a mapping also `via: "federation"`, `idp_id` |
| `directory_role.assign`, `directory_role.unassign` | → user | `role`, `assignment_id` |
| `application.create`, `application.update`, `application.delete`, `application.secret_add`, `application.secret_remove`, `application.scope_add`, `application.scope_update`, `application.scope_remove`, `application.role_add`, `application.role_update`, `application.role_remove`, `application.permission_add`, `application.permission_remove` | → application | `client_id`, `fields`, `secret_id` (+ `never_expires`, `caller_supplied` on `secret_add`), `scope_id`/`role_id` + `value`, `permission_id` |
| `app_role_assignment.create`, `app_role_assignment.delete` | → assignment | create: `resource_client_id`, `role`, `principal_type`, `principal_id`; delete: `resource_client_id`, `app_role_id` |
| `consent.grant`, `consent.revoke` | → consent grant (or client app) | `client_id`, `resource_client_id`, `scopes`, `app_roles`, `user_id` |

Details never contain passwords, secrets, codes or tokens. Rate-limited
sign-in attempts are not logged (they cost an attacker nothing). Events are
deleted after the tenant's `audit_retention_days` (default 90) by the
sweeper job.

## Me

`/api/v1/me…` (self-service, any user's delegated token): see [me.md](me.md).
