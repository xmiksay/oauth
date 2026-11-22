# Management API — applications (`/api/v1/applications`)

Part of the [management API](management.md) (authentication, conventions,
the `Application` object and audit events there). Read: any role; write:
GlobalAdmin, ApplicationAdmin, `ReadWrite.All`.

| Method & path | Body | Response |
|---|---|---|
| `GET applications` *paged* `?search=` (name, client_id) | – | `Application`s |
| `POST applications` | `{ display_name, client_id?, client_type? (confidential), redirect_uris?, post_logout_redirect_uris?, web_origins?, identifier_uri?, access_token_format?, signing_alg?, groups_claim_format?, id_token_groups? (none), assignment_required? (false), access_token_ttl_secs?, refresh_token_ttl_secs?, device_code_enabled? (false), mfa_policy? (inherit), backchannel_logout_uri? (null), backchannel_logout_session_required? (false) }` | 201 `Application` |
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
  protocol endpoints cross-origin (CORS, [cors.md](../cors.md)),
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
  groups → no `groups`, `hasgroups: true`. The same format applies to the
  `groups` of ID tokens and userinfo **issued to** this app.
- `id_token_groups` `none|all|assigned` (default `none`; not editable on
  built-in apps): whether ID tokens and userinfo responses **issued to** this
  app as a client carry a `groups` claim — every group of the user (`all`)
  or only the groups holding one of this app's roles open to users
  (`assigned`), in this app's `groups_claim_format`, with the overage rule
  above (counted after the `assigned` filter). For sign-in clients that
  authorize by the ID token (Headlamp → kube-apiserver, Grafana, ArgoCD).
  Only this field decides: the `groups` scope is accepted but releases
  nothing by itself, and an app with `none` gets no claim even when it asks
  for it.
- `device_code_enabled` (boolean): the app may use the device authorization
  grant (`/oauth2/devicecode` + the `device_code` token grant, see
  [../device_code.md](../device_code.md)).
  Not settable on built-in apps (403).
- `mfa_policy` `inherit|required` (default `inherit`; a GlobalAdmin may set
  it on built-in apps too): `required` makes every sign-in to the app — as
  the client, or when its scopes are requested as the resource — multi-factor
  even under a tenant policy of `optional` (forced enrolment / step-up as in
  [../authn.md](../authn.md#mfa-policy)); a refresh token of a single-factor
  sign-in is refused (`invalid_grant`) when redeemed for the app as another
  resource (multi-resource refresh). There is no `optional`: an app can
  only tighten the tenant's `mfa_policy`.
- `backchannel_logout_uri` (string or `null` to clear): OIDC Back-Channel
  Logout endpoint — absolute `https`, no fragment or credentials, ≤ 2048
  bytes, a public IP if a literal; plain `http` only to loopback in
  development (400 otherwise). `backchannel_logout_session_required`
  (boolean; `sid` is always sent anyway). Not settable on built-in apps
  (403). See [../backchannel_logout.md](../backchannel_logout.md).

- `assignment_required` boolean (default `false`; not editable on built-in
  apps): only users holding one of the app's user roles (directly or via a
  group) can sign in to it or get delegated tokens for it, and only apps
  holding one of its application permissions get app-only tokens for it.
  Refusals: authorize → `access_denied`, token endpoint → `invalid_grant`;
  re-checked on every code redemption and refresh, including a refresh
  for another resource (multi-resource refresh). Rules in
  [../consent.md](../consent.md#assignment-required).

## Secrets

| Method & path | Body | Response |
|---|---|---|
| `GET applications/{id}/secrets` | – | `{ items: ClientSecret[] }` (never values) |
| `POST applications/{id}/secrets` | `{ description?, expires_in_days? (1–730, default 180), never_expires?, secret? }` | 201 `ClientSecret`; with a generated value also `"secret"`: the value, shown only now |
| `DELETE applications/{id}/secrets/{secret_id}` | – | 204 |

Public clients can't have secrets (400).

- **Caller-supplied value** (`secret`, config as code / GitOps): the
  automation registers a value it already holds in its secret manager
  instead of copying a generated one. It must be 32–256 visible ASCII
  characters (no spaces) with at least 128 bits of *estimated* entropy —
  length × the Shannon entropy of the value's own character distribution —
  else 400 (the message never repeats the value). 32 random bytes as base64
  (`openssl rand -base64 32`) or 64 hex digits pass; 32 hex digits, a
  repeated or two-letter value don't. It is stored exactly like a generated
  one (SHA-256 + 3-character `hint`) and never echoed: the response has no
  `"secret"`. Its `hint` is the first 3 hex digits of that SHA-256, not of
  the value (a value at the entropy minimum can't spare 18 bits to every
  directory reader and expiry email). Without `secret` the server generates 256 random bits and
  returns them once, as before. Clients using `client_secret_basic` must
  form-urlencode a value with reserved characters (RFC 6749 §2.3.1).
- **Non-expiring** (`never_expires: true`, exclusive with
  `expires_in_days`): only where the tenant's `allow_non_expiring_secrets`
  is on (else 400; read again, `FOR SHARE`, in the creating transaction, so
  a request in flight when the setting is turned off is refused); `expires_at` is `null`, `never_expires` is `true`.
  Turning the setting off later keeps existing non-expiring secrets until
  they are deleted.
- The `application.secret_add` audit event records `secret_id`,
  `never_expires` and `caller_supplied` (never the value).
- **Expiry warning**: 14 days before a secret expires, the tenant's Global
  Admins and Application Admins get one email
  ([email.md](../email.md#client-secret-expiry)).

## Exposed scopes and app roles

| Method & path | Body | Response |
|---|---|---|
| `GET applications/{id}/scopes` | – | `{ items: Scope[] }` |
| `POST applications/{id}/scopes` | `{ value, description?, admin_consent_required? (false) }` | 201 `Scope` |
| `PATCH applications/{id}/scopes/{scope_id}` | `{ description?, admin_consent_required? }` | `Scope` |
| `DELETE applications/{id}/scopes/{scope_id}` | – | 204; the value is also removed from consent grants, required permissions naming it cascade, refresh-token families whose grant held it are revoked (with their opaque access tokens), and so is every other opaque access token for the app carrying the scope (minted by a multi-resource refresh). Refresh never re-mints a scope the resource no longer exposes |
| `GET applications/{id}/roles` | – | `{ items: AppRole[] }` |
| `POST applications/{id}/roles` | `{ value, display_name, description?, allowed_member_types }` | 201 `AppRole` |
| `PATCH applications/{id}/roles/{role_id}` | `{ display_name?, description?, allowed_member_types? }` | `AppRole` |
| `DELETE applications/{id}/roles/{role_id}` | – | 204 (assignments cascade) |

`value`: 1–120 printable ASCII without space, `"`, `\` or `/`; unique per
app (409); immutable (`value` in PATCH → 400). Scope values must not be
`openid`, `profile`, `email`, `offline_access`, `groups` or `.default` in any case
(400). `allowed_member_types` is a non-empty set ⊆ {`user`, `application`}:
duplicates collapse and it is stored and returned in canonical order
(`["user","application"]`), so a reordered PATCH is no change.

## Required permissions

| Method & path | Body | Response |
|---|---|---|
| `GET applications/{id}/required-permissions` | – | `{ items: RequiredPermission[] }` |
| `POST applications/{id}/required-permissions` | `{ resource_application_id, type: "delegated"\|"application", value }` | 201 `RequiredPermission` (400 if the resource doesn't expose `value`) |
| `DELETE applications/{id}/required-permissions/{permission_id}` | – | 204 |
