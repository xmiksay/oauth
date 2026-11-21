# Device authorization grant (RFC 8628)

Part of the [architecture](architecture.md); the browser-side contract is in
[api/authn.md](api/authn.md#device-code), the `device_code_enabled` flag in
[api/management.md](api/management.md).

RFC 8628, for apps that opted in (`device_code_enabled`, set through the
management API; for an app holding management-API grants only by a
GlobalAdmin, like its redirect URIs; never on built-in apps). Others get
`unauthorized_client` at both endpoints.

- `POST /oauth2/devicecode` (client auth as at the token endpoint, `scope`
  validated like `/authorize`'s, rate limited 30 / 5 min per IP) →
  `device_code` (256-bit bearer), `user_code` (`XXXX-XXXX` over the 20
  consonants `BCDFGHJKLMNPQRSTVWXZ`, ~34.5 bits, unique per tenant),
  `verification_uri` `{issuer}/device`, `verification_uri_complete`
  (`?user_code=`), `expires_in` 900, `interval` 5. Both codes are stored as
  SHA-256 only.
- The user enters the code on the SPA page `/device` → `POST
  /api/authn/device` (CSRF-checked, 10 / 5 min per IP counted before the
  lookup; every failure is the same `invalid_code`) starts an ordinary
  login transaction whose `AuthRequest.device` names the row: sign-in (or the
  browser's session), MFA, forced password change as usual, then the
  consent step — always, even when everything was consented before, so a
  phished code never approves silently; it lists every scope the device
  gets (resource scopes, and `profile` / `email` / `offline_access` from the
  view's `oidc_scopes`, so the user learns the device stays signed in).
  Admin-consent-only scopes deny the request — with a browser session at
  code entry already, before any transaction is made (like `/authorize`),
  otherwise right after sign-in. Approving records the
  user and the browser session's `amr` / `auth_time` on the row (CAS on
  `pending` + unexpired) in the completion's transaction; Deny records
  `denied`. The browser ends on `/device?result=approved` or
  `/device?error=…` ([api/authn.md](api/authn.md#device-code)).
- Token endpoint, `grant_type=urn:ietf:params:oauth:grant-type:device_code`
  + `device_code`: the row is taken `FOR UPDATE`, so polls, the decision's
  CAS and redemption serialize. Unknown / another client's / redeemed →
  `invalid_grant`; expired → `expired_token`; `denied` → `access_denied`;
  `pending` → `authorization_pending`, or `slow_down` when the poll came
  sooner than `interval_secs` after the previous one (1 s jitter allowed),
  which adds 5 s for all later polls (capped at 60). `approved` → consumed
  and tokens issued in the same transaction (single use): the device gets a
  **session of its own** (no cookie; its id is the tokens' `sid`; `amr` /
  `auth_time` of the approving sign-in; listed in My Account and revocable
  there like any session, which also revokes its refresh tokens), an access
  token as in the code flow, an ID token with `openid` (no `nonce`) and a
  refresh token with `offline_access`.
- Audited: `device_code.approve` / `device_code.deny` (the user, target the
  client app; deny `reason` `declined` or `admin_consent_required`) and
  `device_code.redeem` (the client, target the user, with the new session).
