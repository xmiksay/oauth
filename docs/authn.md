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
| `password` | password, passwordless passkey, `federation/{idp}` (upstream round trip) | `mfa` if the user has a factor (unless a passkey or a trusted upstream MFA already made it multi-factor), `mfa_enroll` if MFA is required and they have none, `link` for an unknown upstream identity under `link_only`, else `change_password` / `consent` / done |
| `link` | password or passkey of the local account that should own the pending upstream identity (`pending_identity`) | as after `password`; the identity is linked in the transaction that completes the sign-in |
| `mfa` | TOTP, recovery code, passkey, Telegram code | `change_password` / `consent` / done |
| `mfa_enroll` | a new TOTP secret confirmed with a code, or a new passkey | `change_password` / `consent` / done |
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

`acr`: ID and access tokens carry `"acr": "mfa"` when `amr` contains `mfa`
(a local second factor, a passwordless passkey, or an upstream trusted for
MFA); single-factor sign-ins have no `acr`. Discovery lists
`acr_values_supported: ["mfa"]`; the `acr_values` request parameter is not
interpreted (the policy below decides).

## MFA policy

`tenants.mfa_policy` (`optional` default | `required`) and
`applications.mfa_policy` (`inherit` default | `required`: an app can only
tighten). A sign-in needs MFA when the tenant, the client app or the
requested resource app requires it (`authn::mfa_policy`). It is checked
whenever a sign-in step would complete the sign-in (`complete::proceed`,
before `change_password` and `consent`) and whenever `/authorize` or the
device flow would reuse a session:

- The user has a factor (TOTP, passkey, Telegram — fail closed without a
  bot as for `mfa`): stage `mfa`.
- They have none: stage `mfa_enroll` — they set up TOTP (recovery codes are
  issued as in My Account) or a passkey inside the login transaction; it is
  audited (`user.mfa.totp_enroll` / `user.mfa.passkey_register`, `via:
  sign_in`), the user is notified, and the new factor counts as this sign-in's
  second factor. Only someone who just passed the first factor in this
  transaction gets here, which is the usual trade-off of forced enrolment:
  the first factor alone lets the user (or whoever holds it) register the
  first second factor. A confirmed TOTP answers with the recovery codes
  only; the transaction waits at `mfa_enroll` until `…/enroll/continue`, so
  the authorization code (60 s) isn't issued while the user saves them.
- A single-factor session is stepped up instead of reused. If the user has
  a factor: a transaction at `mfa` for the session's user (keeping its
  `amr` / `auth_time`) whose completion upgrades that session in place: same
  id (the `sid` claim; its refresh tokens and codes stay bound to it, so
  signing it out still revokes them), the multi-factor `amr`, `auth_time` =
  the step-up's completion (when the second factor was just verified), a
  rotated cookie value and a renewed lifetime — only if that session is still live then (locked in
  the completing DB transaction; a session signed out or revoked meanwhile
  ends the sign-in with `login_required`). If they have none: a fresh
  sign-in at `password` (as `prompt=login`), never enrolment on the session
  cookie alone — that would let a stolen session register a passkey, which
  My Account guards with reauthentication. `prompt=none` gets
  `interaction_required`.
- An upstream sign-in counts as MFA only when the IdP is trusted for it
  (`trust_upstream_mfa`, [federation.md](federation.md)).

The policy is read at sign-in / authorize time: tokens already issued and
refresh grants of existing families are not affected by a later change.

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
| device user codes entered per IP / device codes requested per IP | 10 / 5 min, 30 / 5 min |
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
