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
  token always carries `sid`, so it is always satisfied.

Discovery advertises `backchannel_logout_supported` and
`backchannel_logout_session_supported` as `true`. ID tokens (and delegated
access tokens) carry `sid` = the session id.

### Recipients

Every delegated token issuance (code, refresh, device code grants) records
its client in `session_clients (tenant_id, session_id, application_id)`
(only while the session exists; rows cascade with the session — including
expiry sweeps — and with the application). When sessions end, the action's
transaction first calls `backchannel::queue`, which puts one `backchannel`
outbox row per (ended session, recorded client that has a
`backchannel_logout_uri` now). Sessions end through: RP-initiated logout,
My Account session revocation (one / all), admin `revoke-sessions`,
password change / reset (other sessions), disabling a user, and a new
sign-in replacing another session in the same browser. **Sessions that just
expire notify nobody.**

The outbox row: `recipient` = application id, `kind` =
`backchannel_logout`, sealed body `{"sid", "sub"}`, 24 h lifetime.

### Delivery

`jobs::outbox` runs the `backchannel` channel every tick (always on) with
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
(`http::client`: rustls on AWS-LC, no redirects, no proxy, 10 s total / 5 s
connect) and, outside development, resolves through
`federation::resolve::PublicOnly` (no private, loopback or link-local
destinations). A disabled tenant's rows are dead.

Never logged: the logout token, the endpoint URL, a reqwest error's text.
Logs carry the outbox message id, status code and error kind only.
