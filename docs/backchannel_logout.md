# Logout and Back-Channel Logout

How ending a browser session reaches refresh tokens and other relying
parties. Code: `oidc::logout`, `backchannel` (`mod.rs` recipients + queue,
`token.rs` the logout token, `deliver.rs` the outbox `Courier`).

## Refresh tokens on logout

Tenant setting `logout_revokes_refresh_tokens` (default **on**, `PATCH
/api/v1/settings`, admin **Settings** page): RP-initiated logout
(`GET /oauth2/logout` with a valid hint, or the confirmation page's
`POST`) revokes the refresh-token families started in the ended session and
their opaque access tokens (`tokens::refresh::revoke_by_session`), in the
same transaction that deletes the session. Every refresh token is bound to
its session at issuance (`refresh_tokens.session_id`, kept through
rotation), so there is nothing to bind later. Off: logout ends only the
browser session; offline access lives on.

Explicit session revocation — My Account "sign out this device" / "sign out
everywhere", an admin's `revoke-sessions`, password changes and resets,
disabling a user — always revokes the tokens, whatever the setting.

## Back-Channel Logout 1.0

Per application (`PATCH /api/v1/applications/{id}`, admin app
**Authentication** tab):

- `backchannel_logout_uri`: absolute `https` URL, no fragment, no
  credentials, ≤ 2048 bytes; an IP literal must be public. Plain `http` only
  to a loopback host while `PUBLIC_URL` is `http://` (development, tests).
  Changing it is gated like redirect URIs (privileged apps: GlobalAdmin
  only); not settable on built-in apps.
- `backchannel_logout_session_required`: stored and returned; the logout
  token always carries `sid`, so it is always satisfied. The admin UI
  offers it only while a URI is set and clears it with the URI.

Discovery advertises `backchannel_logout_supported` and
`backchannel_logout_session_supported` as `true`. ID tokens (and delegated
access tokens) carry `sid` = the session id.

### Recipients

Every delegated token issuance (code, refresh, device code grants) records
its client — first, before any token bound to the session is inserted — in `session_clients (tenant_id, session_id, application_id)`
(only while the session exists; rows cascade with the session — including
expiry sweeps — and with the application). When sessions end, the action's
transaction first calls `backchannel::queue`, which puts one `backchannel`
outbox row per (ended session, recorded client that has a
`backchannel_logout_uri` now). Sessions end through: RP-initiated logout,
My Account session revocation (one / all), admin `revoke-sessions`,
password change / reset (other sessions), disabling or deleting a user
(its outbox rows outlive it), and a new sign-in replacing another session
in the same browser. **Sessions that just
expire notify nobody.**

Ordering: `queue` first locks the ended sessions `FOR UPDATE` (in id
order, so two revocations of one user's sessions can't deadlock);
`record_client` locks the user, then its session, `FOR KEY SHARE`. A token issuance racing
a logout therefore either commits first (and its client is notified) or
waits and then finds the session gone (no row, no FK error). The
`authorization_code` grant requires the session: it calls `record_client`
before consuming the code and answers `invalid_grant` when the session has
ended, so a code redeemed after (or losing a race with) its logout issues
nothing, and one that wins the race holds the session until commit — the
logout then revokes its refresh token and notifies its client.
Lock order is user, then session, then tokens, on every path: admin
revocation / disabling / password resets lock the user `FOR UPDATE` before
`queue`; logout and session revocation lock the session before
`revoke_by_session` updates its tokens; issuance calls `record_client`
first — the code grant before consuming the code, the refresh grant before
`mark_rotated` locks the presented token. The user is locked even when the
session is gone, since inserting a token takes the user's key lock (FK)
too; any other order deadlocks against the admin paths. The same
`backchannel::lock_user` comes first wherever a session of the user is
locked or rows referencing the user are inserted: sign-in completion
(`authn::complete::finish`, after the IdP lock, before the login
transaction, the session it builds on or the one it replaces), a
federated sign-in (after the IdP lock, before touching the identity and
applying group mappings), the refresh grant (right after `BEGIN`, before a
multi-resource refresh locks consent rows) and the device code grant (the
approving user before the request row), and denying a device request
(`authn::device_code::deny`, which writes the user into the request row;
callers that also claim a login transaction lock the user before it). A
refresh that loses this race gets a plain `invalid_grant` — a token
revoked (not rotated) meanwhile is no replay, so no reuse alarm.

`lock_user` returns the user's state as read under the lock
(`UserLock::{Active, Disabled, Gone}`): a disable or deletion that committed
while the caller waited is only visible from there on — a `disabled` read
before the lock is stale. So every issuing path refuses unless the user is
`Active`: sign-in completion answers `403 account_disabled` (no session, no
code, the login transaction stays unclaimed), the code and refresh grants
`invalid_grant` ("the user is disabled or no longer exists"), a federated
sign-in the `account_disabled` refusal (no group mappings written),
`record_client` reports the session as ended, and the device code grant
reads the user after `lock_request` took the lock. A device denial for a
user deleted meanwhile records nothing (the row stays pending).

The outbox row: `recipient` = application id, `kind` =
`backchannel_logout`, sealed body `{"sid", "sub"}`, 24 h lifetime.

### Delivery

`jobs::outbox` runs the `backchannel` channel every tick (always on, on
its own task beside the job loop, one run at a time, so slow RPs never
delay the sweeper or the other channels; its own leader-lock key, so it
never makes email or Telegram skip a tick; up to 32 rows per run, 15 s
budget each) with
the usual lease, backoff (1 m, 5 m, 30 m, 2 h, then 6 h; dead after 8) and
fencing. Each attempt re-reads the application (deleted, no URI or a URI
that no longer passes the policy → dead) and signs a **fresh** logout token
with the app's `signing_alg` and the tenant's active key:

```
header  { "typ": "logout+jwt", "alg", "kid" }
claims  { "iss", "aud": client_id, "iat", "exp": iat + 120, "jti",
          "sub": user id, "sid": session id,
          "events": { "http://schemas.openid.net/event/backchannel-logout": {} } }
```

No `nonce`, ever. It is POSTed as `application/x-www-form-urlencoded`
`logout_token=…`. 2xx → sent; 408 / 429 / 5xx / network errors / timeouts →
retry; any other status → dead. The client is the federation recipe
(`http::client`: rustls on AWS-LC, no redirects, no proxy, 10 s total / 3 s
connect) and, outside development, resolves through
`federation::resolve::PublicOnly` (no private, loopback or link-local
destinations). A disabled tenant's rows are dead.

Never logged: the logout token, the endpoint URL, a reqwest error's text.
Logs carry the outbox message id, status code and error kind only.
