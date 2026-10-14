# Management API — `me` (`/api/v1/me…`)

Part of the [management API](management.md) (authentication, conventions
and objects there).

## Endpoints (delegated token of any user of the tenant)

| Method & path | Body | Response |
|---|---|---|
| `GET me` | – | `Me` = `UserDetail` + `features: { email }` (whether the server can send email) |
| `PATCH me` | `{ display_name }` | `Me` (same shape as `GET me`) |
| `POST me/change-password` | `{ current_password, new_password }` | 204 |
| `POST me/verify-email` | – | 202 `{ sent: true }`: a 24 h verification link to the current address (409 already verified, 400 email not configured) |
| `POST me/email` | `{ new_email, password }` | 202 `{ sent: true }`: a 24 h link to the NEW address; the change applies when it is opened (`POST /api/authn/email/verify`, 409 if the address is taken by then) and notifies the old address if it was verified. Always 202 for a well-formed request with the right password — also for an address that is taken (no probing for accounts). 403 wrong password, 400 invalid / same as current / not configured |
| `GET me/notifications` | – | `{ channels: { email, telegram }, items: [{ event, email, telegram }] }` — all five events (`password_changed`, `mfa_changed`, `email_changed`, `new_sign_in`, `token_reuse`), default on |
| `PUT me/notifications` | `{ items: [{ event, email, telegram? }] }` (any subset; unknown / repeated event → 400) | same as `GET` |
| `POST me/totp` | `{ password }` | `{ secret, otpauth_uri, digits: 6, period: 30, algorithm: "SHA1" }` |
| `POST me/totp/confirm` | `{ code }` | `{ recovery_codes: [10 × "xxxx-xxxx-xxxx"] }` |
| `DELETE me/totp` | `{ password }` | 204: TOTP and recovery codes removed |
| `POST me/recovery-codes` | `{ password }` | `{ recovery_codes }` (replaces all) |
| `GET me/sessions` | – | `{ items: Session[] }` (`current` marks the token's session) |
| `DELETE me/sessions/{id}` | – | 204 |
| `POST me/sessions/revoke-all` | – | 204 |
| `GET me/consents` | – | `{ items: [ConsentGrant + client: {id, client_id, display_name}, resource: {…}] }` (own grants only) |
| `DELETE me/consents/{id}` | – | 204 |

- **Security info changes need the current password** (`POST me/totp`,
  `DELETE me/totp`, `POST me/recovery-codes`; also `change-password`): a
  stolen access token alone can't add, remove or read out a factor. Wrong
  password → 403; attempts count against the same per-account rate limit
  as sign-in (429 + `Retry-After`).
- `verify-email` and `email` count against a per-account mail limit
  (5 / 15 min, 429). Notices go to a verified address only (the
  email-change notice to the old address regardless); see [../email.md](../email.md).
- TOTP enrollment is two-step. `POST me/totp` stores a pending secret
  (replacing an earlier pending one; 409 if a confirmed TOTP exists — remove
  it first; the store itself never overwrites a confirmed factor, so a
  racing enrollment also gets 409) and returns it once (base32, plus an `otpauth://` URI with the
  tenant's display name as issuer). Sign-in ignores it until
  `POST me/totp/confirm` with a current code (400 invalid code, 409 nothing
  pending), which activates it and returns 10 new recovery codes, shown once.
  From then on sign-in asks for a TOTP or recovery code.
- `change-password` follows the sign-in password rules (new ≠ current) and
  ends every **other** session of the user with their refresh / opaque
  access tokens; the session the calling token belongs to (and the refresh
  tokens issued in it) survives, so the SPA keeps working. Admin resets,
  `revoke-sessions` and the sign-in forced change end all sessions.
- `DELETE me/sessions/{id}` signs that device out: the session and the
  refresh-token families started in it (with their opaque access tokens).
  `revoke-all` = every session including the caller's (its management
  token stops working immediately).
- `DELETE me/consents/{id}` deletes the user's own grant and revokes the
  client's refresh / opaque tokens for that resource and user. Tenant-wide
  admin grants are not listed and not revocable here.
