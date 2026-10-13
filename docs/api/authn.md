# Login JSON API (`/{t}/api/authn`) and sign-out page

The contract the SPA pages `/{t}/login?tx=<id>` and `/{t}/logout` (step 5)
call. `/{t}/oauth2/authorize` creates a **login transaction**, sets the
transaction-binding cookie and redirects the browser to
`{PUBLIC_URL}/{t}/login?tx=<id>`; the SPA then walks the steps below until
the API answers with a `redirect`, which the SPA follows
(`window.location.assign`).

## Conventions

- **Browser binding.** Every call (including `GET`) must carry the
  `__Host-oauth_tx` cookie that `/authorize` set in this browser (`oauth_tx`
  with `COOKIE_SECURE=false`; `HttpOnly`, `Secure`, `Path=/`,
  `SameSite=Lax`, `Max-Age` = 15 min, refreshed by every `/authorize`).
  Same-origin `fetch` sends it automatically. A missing or foreign cookie
  answers exactly like an unknown transaction (`404 not_found`), so a leaked
  or planted `tx` id is useless in another browser. The cookie is shared by
  all tabs and tenants of the browser and never cleared explicitly (it just
  expires), so several sign-ins can run in parallel tabs.
- **CSRF.** All `POST`s must send `Content-Type: application/json` **and**
  an `Origin` equal to the origin of `PUBLIC_URL` (no CORS is ever granted,
  so cross-site JSON posts can't be made). Violations: `400 invalid_request`
  (content type) / `403 csrf_rejected` (origin).
- A transaction lives 15 minutes and is deleted when the flow completes or
  is declined. Unknown / expired / foreign ids → `404 not_found`.
- Calling a step the transaction is not at → `409 wrong_step`.
- Errors are always JSON: `{ "error": "<code>", "error_description": "<text>" }`
  — also for malformed bodies (`400 invalid_request`, never plain text).
- Responses are `Cache-Control: no-store`. Every response of the server
  carries `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors
  'none'` and `Referrer-Policy: no-referrer` (the SPA must not rely on being
  framed or on `Referer`).

## Step view (`GET /{t}/api/authn/tx/{id}` and every non-final `POST`)

```json
{
  "tx": "6a0c…",
  "step": "password | mfa | change_password | consent",
  "tenant": { "slug": "contoso", "display_name": "Contoso" },
  "client": { "client_id": "web-app", "display_name": "Web App" },
  "user": { "email": "ann@example.com", "display_name": "Ann" },
  "consent": {
    "resource": { "display_name": "Orders API", "audience": "api://orders" },
    "scopes": [{ "value": "Orders.Read", "description": "Read your orders" }]
  }
}
```

`user` is `null` until the password step succeeded; `consent` is `null`
unless `step` is `consent` (it then lists only the scopes awaiting approval —
previously granted ones are not repeated).

## Final response

```json
{ "redirect": "https://app.example/cb?code=…&state=…&iss=…" }
```

It sets the session cookie **only when
a new session was created** (not when a consent-only transaction reused the
existing session). Protocol errors that belong to the client are also a
`redirect`, to the client's redirect URI with `error`, `error_description`,
`state`, `iss`: `access_denied` (user declined, or an admin-only scope lacks
admin consent — "admin approval required for: …"), `login_required` (a
reused session ended while consent was pending).

## Steps

| `POST …/tx/{id}/` | Body | When |
|---|---|---|
| `password` | `{ "email", "password" }` | step `password` |
| `totp` | `{ "code": "123456" }` | step `mfa` (user has a confirmed TOTP); a code is accepted once |
| `recovery` | `{ "code": "abcd-efgh-…" }` | step `mfa`; one-time recovery code (case, spaces and `-` ignored) |
| `change-password` | `{ "new_password" }` | step `change_password` (`must_change_password`) |
| `consent` | `{ "approve": true, "scopes": ["Orders.Read"] }` or `{ "approve": false }` | step `consent`; approving must list every scope shown (all-or-nothing) |

Order: `password` → `mfa` (if TOTP confirmed) → `change_password` (if
required) → `consent` (if needed) → redirect. A transaction created for a
user who already has a session but must consent starts at `consent`.
Setting the new password ends the user's other sessions and revokes their
refresh tokens and opaque access tokens. A completed sign-in replaces any
earlier session of this browser (e.g. after `prompt=login`).

## Errors

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_request` | Malformed JSON / missing fields; wrong `Content-Type`; an email containing control characters (rejected before any lookup or rate-limit bucket); consent approval not listing every shown scope; `change-password` with a password outside 12–256 chars or equal to the current one |
| 401 | `invalid_credentials` | Wrong email or password, or unknown email — never distinguished (unknown accounts are verified against a dummy argon2 hash to equalise timing) |
| 401 | `invalid_code` | Wrong / reused TOTP code or recovery code |
| 403 | `account_disabled` | Correct password, but the user is disabled |
| 403 | `csrf_rejected` | `Origin` missing or not `PUBLIC_URL`'s |
| 404 | `not_found` | Unknown, expired, finished or foreign transaction (`no-store`). An unknown or disabled tenant also answers `404 {"error":"not_found","error_description":"resource not found"}`, from the tenant resolver (without `no-store`) |
| 409 | `wrong_step` | The transaction is at another step (or a concurrent call advanced it) |
| 429 | `rate_limited` | Too many attempts; `Retry-After` header in seconds |
| 500 | `server_error` | Internal fault (logged; no detail in the body) |

## Rate limits

Fixed windows, shared by all replicas through Postgres; every attempt counts,
successes too. IPv6 clients are bucketed per /64.

| Bucket | Limit | Applies to |
|---|---|---|
| client IP, per tenant | 30 / 5 min | `password`, `totp`, `recovery`, `change-password` |
| account, per tenant | 10 / 15 min | same; keyed by user id once the email resolves, else by the trimmed, lower-cased email |
| client IP, per tenant | 60 / 5 min | `/oauth2/authorize` requests that create a login transaction → `429` JSON (`rate_limited`), not a redirect |

## Session cookie

`__Host-oauth_sid_{t}=<random>; Path=/; Max-Age=SESSION_TTL_HOURS*3600;
HttpOnly; SameSite=Lax; Secure` — one cookie per tenant (the `__Host-` prefix
forbids a per-tenant `Path`, so the tenant is in the name; the prefix also
stops sibling subdomains from planting cookies). With `COOKIE_SECURE=false`
(plain-http local dev only) the names lose the prefix (`oauth_sid_{t}`,
`oauth_tx`) and `Secure`. The server keeps only the SHA-256 of the value.

## Sign-out confirmation page (`/{t}/logout`)

`GET /{t}/oauth2/logout` ends the session directly only with a valid
`id_token_hint` whose `sub` is the session's user; it then redirects to the
client's registered `post_logout_redirect_uri`, or — without one — to
`{PUBLIC_URL}/{t}/logout?signed_out=1`, where the page just shows "You have
been signed out" (no confirmation, no API call). Otherwise (no hint, an
invalid one, or another user's) it ends nothing and redirects to
`{PUBLIC_URL}/{t}/logout` without parameters (it never redirects to a
`post_logout_redirect_uri` without a valid hint). That page asks "Sign out?"
and on confirmation calls:

```
POST /{t}/oauth2/logout
Content-Type: application/json
Origin: {PUBLIC_URL origin}

{}
```

→ `200 { "signed_out": true }`, deletes the session and clears the session
cookie (also when there was no session). The CSRF rules above apply
(`400` / `403`).
