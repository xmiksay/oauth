# Sign-in (`authn`)

How a browser signs in on a tenant host. The JSON contract the SPA drives
is [api/authn.md](api/authn.md); the methods each have their own page:
email links [email.md](email.md), passkeys [passkeys.md](passkeys.md),
Telegram codes [telegram.md](telegram.md), upstream identity providers
[federation.md](federation.md).

## Login transactions

`/oauth2/authorize` without a usable session creates a `login_transactions`
row (15 min, random UUIDv4 handle, bound to the browser's tx-binding cookie)
and sends the browser to `/login?tx=…`. Its `stage` moves forward with
compare-and-set updates, so a step submitted twice advances it once:

| Stage | Accepts | Next |
|---|---|---|
| `password` | password, passwordless passkey, `federation/{idp}` (upstream round trip) | `mfa` if the user has a factor (unless a passkey or a trusted upstream MFA already made it multi-factor), `link` for an unknown upstream identity under `link_only`, else `change_password` / `consent` / done |
| `link` | password or passkey of the local account that should own the pending upstream identity (`pending_identity`) | as after `password`; the identity is linked in the transaction that completes the sign-in |
| `mfa` | TOTP, recovery code, passkey, Telegram code | `change_password` / `consent` / done |
| `change_password` | a new password | `consent` / done |
| `consent` | approve / decline | done |

Done = `complete::finish`: in one DB transaction the login transaction is
taken (deleted at its stage — a duplicate gets nothing), the session
created, a pending identity linked, the sign-in audited and the code issued.

`amr`: `["pwd"]`, `["pwd","otp","mfa"]` after a TOTP, recovery or Telegram code,
`["pwd","hwk"|"swk","mfa"]` after a passkey as second factor,
`["hwk"|"swk","user","mfa"]` for a passwordless passkey sign-in, `["fed"]` after an
upstream sign-in (`["fed","mfa"]` when the IdP is trusted for MFA and reported it,
`["fed","otp","mfa"]` etc. after a local second factor).

## Sessions & CSRF

Session cookie `__Host-oauth_sid` (`oauth_sid` with `COOKIE_SECURE=false`),
host-only so each tenant host has its own; session lookup is also filtered
by the host's tenant. `Path=/`, `HttpOnly`, `Secure`, `SameSite=Lax` (sent on
the RP's top-level GET to `/authorize`, not on cross-site POSTs); `__Host-`
stops sibling tenant hosts from planting cookies. `/authorize` also sets
`__Host-oauth_tx` (per host, refreshed per request, never cleared so
parallel tabs work), whose hash each login transaction stores: the
login API serves a transaction only to the browser that started it (no
cross-browser completion, no login CSRF / session fixation through a planted
`tx`). The same cookie binds upstream round trips (`federation_states`), so a
federation callback completes only in the browser that left. The login API
and `POST /oauth2/logout` require `Content-Type: application/json` and
`Origin` = the tenant's own origin on every POST (another tenant's pages are
cross-origin, hence rejected); `GET /federation/callback` is protected by its
single-use `state` instead. A new sign-in deletes the browser's previous
session and records the browser's device cookie `__Host-oauth_dev` (random,
1 year, `HttpOnly`, `SameSite=Lax`; an unknown device for that user queues a
"new sign-in" notice); setting a password deletes all the user's sessions and
revokes their refresh / opaque tokens. Client IP (rate limits, session
record) = socket peer, or with `TRUSTED_PROXY_HEADER` the right-most entry of
that header (one trusted proxy hop assumed); IPv6 is bucketed per /64.
Request logs record method + route template only — never the query string
(codes, hints, transaction ids, upstream `state`s).

## Rate limits (`authn::rate_limit`, Postgres fixed windows)

| Bucket | Limit |
|---|---|
| password / factor attempts per IP | 30 / 5 min |
| attempts per account (also re-authentication) | 10 / 15 min |
| `/authorize` transactions per IP | 60 / 5 min |
| home-realm discovery per IP | 30 / 5 min |
| upstream sign-ins started per IP | 30 / 5 min |
| password-reset requests per IP / per address | 10 / 15 min, 3 / 15 min |
| email-link redemptions per IP | 30 / 5 min |
| self-service mails per account | 5 / 15 min |

## Last sign-in method

A user keeps at least one way in: a password, a passkey or a linked
upstream identity at an enabled provider (`federation::identities::Methods`). Removing the last
passkey or unlinking the last identity is refused (409), an admin's Reset
MFA refuses when only passkeys would remain without a password or identity,
and an invitation can be re-sent only while the user has none. Disabling or
deleting an identity provider is allowed; the API reports how many users
it would lock out (`users_only_via`).
