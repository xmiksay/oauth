# Login JSON API (`/api/authn`) and sign-out page

Every path here is on the tenant's own host `{origin}` =
`{scheme}://{t}.{PUBLIC_URL host}[:port]` (unknown hosts → 404). The contract
the SPA pages `/login?tx=<id>` and `/logout` call. `/oauth2/authorize`
creates a **login transaction**, sets the transaction-binding cookie and
redirects the browser to `{origin}/login?tx=<id>`; the SPA then walks the steps below until
the API answers with a `redirect`, which the SPA follows
(`window.location.assign`).

## Conventions

- **Browser binding.** Every call (including `GET`) must carry the
  `__Host-oauth_tx` cookie that `/authorize` set in this browser (`oauth_tx`
  with `COOKIE_SECURE=false`; `HttpOnly`, `Secure`, `Path=/`,
  `SameSite=Lax`, `Max-Age` = 15 min, refreshed by every `/authorize`).
  Same-origin `fetch` sends it automatically. A missing or foreign cookie
  answers exactly like an unknown transaction (`404 not_found`), so a leaked
  or planted `tx` id is useless in another browser. The cookie is host-only
  (one per tenant host), shared by all tabs and never cleared explicitly (it
  just expires), so several sign-ins can run in parallel tabs.
- **CSRF.** All `POST`s must send `Content-Type: application/json` **and**
  an `Origin` equal to the tenant's own `{origin}` — another tenant's host is
  a different origin and is rejected (no CORS is ever granted, so cross-site
  JSON posts can't be made). Violations: `400 invalid_request`
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

## Step view (`GET /api/authn/tx/{id}` and every non-final `POST`)

```json
{
  "tx": "6a0c…",
  "step": "password | link | mfa | change_password | consent",
  "tenant": { "slug": "contoso", "display_name": "Contoso" },
  "client": { "client_id": "web-app", "display_name": "Web App" },
  "user": { "email": "ann@example.com", "display_name": "Ann" },
  "consent": {
    "resource": { "display_name": "Orders API", "audience": "api://orders" },
    "scopes": [{ "value": "Orders.Read", "description": "Read your orders" }]
  },
  "factors": ["password", "passkey"],
  "idps": [{ "id": "0192…", "name": "Contoso SSO" }],
  "idp_hint": null,
  "link": null,
  "notice": null,
  "features": { "password_reset": true, "federation": true }
}
```

`user` is `null` until the password step succeeded; `consent` is `null`
unless `step` is `consent` (it then lists only the scopes awaiting approval —
previously granted ones are not repeated). `features.password_reset` is
true when the server can send email (show "Forgot password?").
`factors` lists what the current step accepts: at `password` always
`["password", "passkey"]` (offered whether or not the account has one, so
it reveals nothing); at `mfa` the subset of `["totp", "recovery",
"passkey", "telegram"]` the user has (`telegram`: a linked chat; on a server
without a bot only when the user has no other factor, and it then answers
`503 telegram_unavailable` — [../telegram.md](../telegram.md)); at `link`
`["password", "passkey"]`; `[]` at other steps.
`idps` (password step only): enabled, visible identity providers for "Sign in
with …" buttons. `idp_hint` (password step only): the enabled provider the
authorize request named with `idp={id}` or `domain_hint={domain}`, else `null`.
`link` (step `link` only): `{ "idp": { "id", "name" }, "email", "name" }` of
the upstream identity waiting to be linked. `notice` (password step):
`"link_unavailable"` when a parked identity was dropped because its provider
was disabled, deleted or no longer `link_only`, else `null`. `features.federation`: the
tenant has an enabled provider (offer email-domain discovery).

## Federation

Flows and security model in [../federation.md](../federation.md).

| Call | Body | Response |
|---|---|---|
| `POST …/tx/{id}/federation/{idp}` | `{}` | step `password`: `200 { "redirect": "<provider authorization URL>" }` — navigate there (full page); `prompt=login` / `max_age` of the authorization request are passed on. `404 not_found` unknown / disabled provider, `502 upstream_failed` when its discovery document can't be used (remembered 30 s), `429` over 30 / 5 min per IP |
| `POST …/tx/{id}/discover` | `{ "email" }` | step `password`: `200 { "idp": { "id", "name" } }` when the address's domain belongs to an enabled provider, else `200 {}` (domain mapping only, nothing about accounts); 30 / 5 min per IP |
| `GET /federation/callback?code&state` | — | The provider's redirect (no `Origin` / JSON rules; protected by the single-use, browser-bound `state`). Always a `302` |

Callback outcomes: `{origin}/login?tx={id}` (load the view: now at `mfa`,
`link`, `change_password` or `consent`), the client's redirect URI (signed in),
`{origin}/login?tx={id}&error={code}` (transaction still at `password`), or
`{origin}/login?error=upstream_failed` (no live, browser-bound state — the
transaction is gone, expired or the link was opened elsewhere). For My
Account links: `{origin}/myaccount/security?federation=linked` or
`?federation_error={upstream_failed|already_linked|account_disabled}`.

| `error` | Meaning |
|---|---|
| `upstream_failed` | The provider or its response failed a check (reason in the audit log only) |
| `upstream_no_email` | Policy `jit` without a verified upstream email |
| `account_exists` | Policy `jit` and a user has that email — sign in and link instead (never linked automatically) |
| `account_disabled` | The linked user is disabled |
| `not_linked` | Policy `deny` and the identity isn't linked |
| `email_domain_not_allowed` | Policy `jit`, the IdP lists `email_domains` and the verified email is of another domain |

At step `link` the `password` and `passkey` calls take the local account's
credentials; completing the sign-in links the identity. They answer
`409 already_linked` when that account already has an identity at the
provider, and `409 link_unavailable` when the provider can no longer link
(the transaction is then back at `password`). Should the provider become
unusable (or the identity get linked elsewhere) only later, at `mfa`,
`change_password` or `consent`, the sign-in still completes without the
link (audited as a failed `user.identity_link`); nothing in the response
says so — the user can link again from My Account.
My Account callbacks also return `federation_error=session_ended` when the
session that started the link has ended.

## Email links (no transaction)

Same CSRF rules and error shape; no tx cookie needed — the token from the
link is the credential. Flows in [../email.md](../email.md).

| `POST` | Body | Response |
|---|---|---|
| `/api/authn/password-reset` | `{ "email" }` | `202 { "accepted": true }` for every well-formed address, known or not, answered before the account is even looked up (a link goes only to an enabled user with a verified address or a pending invitation). `404 not_found` when email isn't configured |
| `/api/authn/email/reset` | `{ "token", "new_password" }` | `204`; the password is set, every session and refresh / opaque token of the user ends, MFA stays required |
| `/api/authn/email/invite` | `{ "token", "new_password" }` | `204`; first password set, address verified |
| `/api/authn/email/invite/passkey/options` | `{ "token" }` | `200 { "publicKey": PublicKeyCredentialCreationOptionsJSON }` (see [Passkeys](#passkeys)) |
| `/api/authn/email/invite/passkey` | `{ "token", "credential": RegistrationJSON, "name"? }` | `204`; a passkey instead of a password, address verified, the user's other invitations voided; a rejected credential → `400 invalid_request` (the token stays usable) |
| `/api/authn/email/verify` | `{ "token" }` | `200 { "purpose": "verify" \| "change", "email" }`; `409 conflict` when a changed-to address was taken meanwhile |

Links carry the token in the fragment (`…#token=…`); the SPA posts it. A
token works once, before it expires, on the host of the tenant that issued
it, for an enabled user whose address is still the one it was sent to (an
invitation also only while the user has neither a password nor a passkey);
anything else is
`400 invalid_token` (never distinguished). Password rules as for `change-password`.

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
| `password` | `{ "email", "password" }` | step `password` or `link` |
| `totp` | `{ "code": "123456" }` | step `mfa` (user has a confirmed TOTP); a code is accepted once |
| `recovery` | `{ "code": "abcd-efgh-…" }` | step `mfa`; one-time recovery code (case, spaces and `-` ignored) |
| `passkey/options` | `{}` | step `password`, `link` or `mfa`: `200 { "publicKey": PublicKeyCredentialRequestOptionsJSON }` (not a step view) |
| `passkey` | AssertionJSON | step `password` / `link` (passwordless) or `mfa` (second factor) |
| `telegram/send` | `{}` | step `mfa` (user has `telegram`): sends a 6-digit code to the linked chat, replacing an earlier one; `200 { "sent": true, "expires_in": 300 }` (not a step view). `502 delivery_failed` when Telegram didn't take it (retry), `400 invalid_request` when no chat is linked, `503 telegram_unavailable` without a bot |
| `telegram` | `{ "code": "123456" }` | step `mfa`: the code last sent (5 min, single use, 5 guesses — then send a new one; spaces ignored) |
| `change-password` | `{ "new_password" }` | step `change_password` (`must_change_password`) |
| `consent` | `{ "approve": true, "scopes": ["Orders.Read"] }` or `{ "approve": false }` | step `consent`; approving must list every scope shown (all-or-nothing) |

Order: `password` → `mfa` (if TOTP confirmed, a passkey registered or a Telegram chat linked) →
`change_password` (if required) → `consent` (if needed) → redirect. A
passkey at the `password` step signs the user in on its own (it skips
`mfa` and `change_password`). A transaction created for a
user who already has a session but must consent starts at `consent`.
Setting the new password ends the user's other sessions and revokes their
refresh tokens and opaque access tokens. A completed sign-in replaces any
earlier session of this browser (e.g. after `prompt=login`).

## Errors

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_request` | Malformed JSON / missing fields; wrong `Content-Type`; an email containing control characters (rejected before any lookup or rate-limit bucket); consent approval not listing every shown scope; `change-password` with a password outside 12–256 chars or equal to the current one |
| 400 | `invalid_token` | Email link token unknown, expired, used, of another tenant, or its user disabled |
| 409 | `conflict` | Email change: the new address was taken meanwhile |
| 401 | `invalid_credentials` | Wrong email or password, or unknown email — never distinguished (unknown accounts are verified against a dummy argon2 hash to equalise timing) |
| 401 | `invalid_credentials` | Any rejected passkey assertion (unknown, other account's, wrong origin / RP, no user verification, bad signature, used / expired challenge, counter regression) — never distinguished; the audit log has the reason |
| 401 | `invalid_code` | Wrong / reused TOTP code or recovery code; wrong, expired, used or dead (5 guesses) Telegram code |
| 403 | `account_disabled` | Correct password, but the user is disabled |
| 403 | `csrf_rejected` | `Origin` missing or not the tenant's `{origin}` |
| 404 | `not_found` | Unknown, expired, finished or foreign transaction (`no-store`). An unknown or disabled tenant (host) also answers `404 {"error":"not_found","error_description":"resource not found"}`, from the tenant resolver (without `no-store`) |
| 409 | `wrong_step` | The transaction is at another step (or a concurrent call advanced it) |
| 429 | `rate_limited` | Too many attempts; `Retry-After` header in seconds |
| 500 | `server_error` | Internal fault (logged; no detail in the body) |
| 502 | `upstream_failed` | `federation/{idp}`: the provider's discovery document failed; any step completing an upstream sign-in whose provider was disabled or repointed since (the transaction is gone) |
| 409 | `already_linked` / `link_unavailable` | Stage `link`, see [Federation](#federation) |
| 502 | `delivery_failed` | `telegram/send`: the Bot API refused or didn't answer (10 s); try again |
| 503 | `telegram_unavailable` | `telegram[/send]` on a server without a Telegram bot (the transaction stays live: use another factor, or an admin resets MFA) |

## Rate limits

Fixed windows, shared by all replicas through Postgres; every attempt counts,
successes too. IPv6 clients are bucketed per /64.

| Bucket | Limit | Applies to |
|---|---|---|
| client IP, per tenant | 30 / 5 min | `password`, `totp`, `recovery`, `passkey`, `telegram`, `change-password` |
| account, per tenant | 10 / 15 min | same; keyed by user id once the email (or the passkey's credential, or the transaction) resolves it, else by the trimmed, lower-cased email (or the credential id) |
| user, per tenant | 3 / 15 min | `telegram/send` (across transactions) |
| client IP, per tenant | 60 / 5 min | `/oauth2/authorize` requests that create a login transaction → `429` JSON (`rate_limited`), not a redirect |
| client IP, per tenant | 10 / 15 min | `password-reset` |
| email address, per tenant | 3 / 15 min | `password-reset`; keyed by the trimmed, lower-cased address whether or not it exists |
| client IP, per tenant | 30 / 5 min | `email/{verify,reset,invite}`, `email/invite/passkey[/options]` |
| client IP, per tenant | 30 / 5 min | `discover` |
| client IP, per tenant | 30 / 5 min | `federation/{idp}` |

## Passkeys

Binary members are base64url without padding; the shapes are the browser's
`PublicKeyCredential.toJSON()` (unknown members ignored). Policy and
verification in [../passkeys.md](../passkeys.md).

```json
// PublicKeyCredentialRequestOptionsJSON (allowCredentials empty at `password`:
// discoverable credentials, `mediation: "conditional"` works)
{ "challenge": "…", "rpId": "contoso.id.example", "timeout": 300000,
  "userVerification": "required",
  "allowCredentials": [{ "type": "public-key", "id": "…", "transports": ["internal"] }] }
// AssertionJSON
{ "id": "…", "rawId": "…", "type": "public-key",
  "response": { "clientDataJSON": "…", "authenticatorData": "…", "signature": "…", "userHandle": "…" } }
// PublicKeyCredentialCreationOptionsJSON
{ "challenge": "…", "rp": { "id": "contoso.id.example", "name": "Contoso" },
  "user": { "id": "<random handle>", "name": "ann@example.com", "displayName": "Ann" },
  "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }, { "type": "public-key", "alg": -8 }, { "type": "public-key", "alg": -257 }],
  "timeout": 300000, "attestation": "none", "excludeCredentials": [],
  "authenticatorSelection": { "residentKey": "required", "requireResidentKey": true, "userVerification": "required" } }
// RegistrationJSON
{ "id": "…", "rawId": "…", "type": "public-key",
  "response": { "clientDataJSON": "…", "attestationObject": "…", "transports": ["internal"] } }
```

A challenge lives 5 minutes, works once, and only the newest one of a
transaction is live — so the SPA aborts a pending conditional request
before asking for fresh options for the button flow.

## Device cookie

Every new sign-in sets `__Host-oauth_dev=<random>; Path=/; Max-Age=31536000;
HttpOnly; SameSite=Lax; Secure` (reused while present). The server keeps
SHA-256 over user id ‖ value (`known_devices`); a sign-in from a browser
unknown for that user queues a "new sign-in" notice, except on the user's
first sign-in ever.

## Session cookie

`__Host-oauth_sid=<random>; Path=/; Max-Age=SESSION_TTL_HOURS*3600;
HttpOnly; SameSite=Lax; Secure` — host-only, so every tenant host has its own
(the server also only looks sessions up within the host's tenant); the
`__Host-` prefix stops sibling tenant hosts from planting cookies. With
`COOKIE_SECURE=false` (plain-http local dev only) the names lose the prefix
(`oauth_sid`, `oauth_tx`) and `Secure`. The server keeps only the SHA-256 of the value.

## Sign-out confirmation page (`/logout`)

`GET /oauth2/logout` ends the session directly only with a valid
`id_token_hint` whose `sub` is the session's user; it then redirects to the
client's registered `post_logout_redirect_uri`, or — without one — to
`{origin}/logout?signed_out=1`, where the page just shows "You have
been signed out" (no confirmation, no API call). Otherwise (no hint, an
invalid one, or another user's) it ends nothing and redirects to
`{origin}/logout` without parameters (it never redirects to a
`post_logout_redirect_uri` without a valid hint). That page asks "Sign out?"
and on confirmation calls:

```
POST /oauth2/logout
Content-Type: application/json
Origin: {origin}

{}
```

→ `200 { "signed_out": true }`, deletes the session and clears the session
cookie (also when there was no session). The CSRF rules above apply
(`400` / `403`).
