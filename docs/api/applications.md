# Management API — applications (`/api/v1/applications`)

Part of the [management API](management.md) (authentication, conventions,
the `Application` object and audit events there). Read: any role; write:
GlobalAdmin, ApplicationAdmin, `ReadWrite.All`.

| Method & path | Body | Response |
|---|---|---|
| `GET applications` *paged* `?search=` (name, client_id) | – | `Application`s |
| `POST applications` | `{ display_name, client_id?, client_type? (confidential), redirect_uris?, post_logout_redirect_uris?, web_origins?, identifier_uri?, access_token_format?, signing_alg?, groups_claim_format?, access_token_ttl_secs?, refresh_token_ttl_secs?, device_code_enabled? (false), mfa_policy? (inherit) }` | 201 `Application` |
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
- `web_origins` (≤ 32, no duplicates): browser origins allowed to read the
  protocol endpoints cross-origin (CORS, [architecture](../architecture.md#cors)),
  exactly as a browser serializes them: `https://host[:port]` (lowercase DNS
  name or IPv4, punycode for IDNs) or `http://127.0.0.1[:port]` /
  `http://[::1][:port]`; no path, trailing `/`, query, fragment, userinfo,
  wildcard or default port (`:443` / `:80`). A public client's redirect-URI
  origins are allowed anyway (`effective_web_origins`).
- `identifier_uri`: `api://{own client_id}` (lowercase scheme, nothing
  else after `api://`), or an `https://` URI without query / fragment; scope
  token characters only, no trailing `/`, ≤ 256; unique per tenant (409).
- `access_token_format` `jwt|opaque`, `signing_alg` `RS256|ES256`,
  `access_token_ttl_secs` 300–86400, `refresh_token_ttl_secs` 1 – 90 days
  (7 776 000) for confidential and 1 – 7 days (604 800) for public clients
  (new public clients default to 24 h; the DB also caps at 90 days). The
  access token format, alg and TTL apply to tokens **for** this app as a
  resource; `signing_alg` also signs ID tokens issued **to** it.
- `groups_claim_format` `id|name` (default `id`; not editable on built-in
  apps): the `groups` claim of delegated access tokens **for** this app as
  a resource carries group ids or group display names (names are unique per
  tenant, case-insensitively, but a rename changes the claim and a deleted
  group's name can be reused — bind authorization to names only where
  that's acceptable). The overage rule is the same for both: more than 200
  groups → no `groups`, `hasgroups: true`.
- `device_code_enabled` (boolean): the app may use the device authorization
  grant (`/oauth2/devicecode` + the `device_code` token grant, see
  [../device_code.md](../device_code.md)).
  Not settable on built-in apps (403).
- `mfa_policy` `inherit|required` (default `inherit`; a GlobalAdmin may set
  it on built-in apps too): `required` makes every sign-in to the app — as
  the client, or when its scopes are requested as the resource — multi-factor
  even under a tenant policy of `optional` (forced enrolment / step-up as in
  [../authn.md](../authn.md#mfa-policy)). There is no `optional`: an app can
  only tighten the tenant's `mfa_policy`.

## Secrets

| Method & path | Body | Response |
|---|---|---|
| `GET applications/{id}/secrets` | – | `{ items: ClientSecret[] }` (never values) |
| `POST applications/{id}/secrets` | `{ description?, expires_in_days? (1–730, default 180) }` | 201 `ClientSecret` + `"secret"`: the value, shown only now |
| `DELETE applications/{id}/secrets/{secret_id}` | – | 204 |

Public clients can't have secrets (400).

## Exposed scopes and app roles

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

## Required permissions

| Method & path | Body | Response |
|---|---|---|
| `GET applications/{id}/required-permissions` | – | `{ items: RequiredPermission[] }` |
| `POST applications/{id}/required-permissions` | `{ resource_application_id, type: "delegated"\|"application", value }` | 201 `RequiredPermission` (400 if the resource doesn't expose `value`) |
| `DELETE applications/{id}/required-permissions/{permission_id}` | – | 204 |
