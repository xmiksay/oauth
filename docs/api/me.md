# Management API — `me` (`/api/v1/me…`)

Part of the [management API](management.md) (authentication, conventions
and objects there).

## Endpoints (delegated token of any user of the tenant)

| Method & path | Body | Response |
|---|---|---|
| `GET me` | – | `Me` = `UserDetail` + `features: { email, telegram }` (whether the server can send email / has a Telegram bot) |
| `PATCH me` | `{ display_name }` | `Me` (same shape as `GET me`) |
| `POST me/change-password` | `{ current_password, new_password }` or `{ passkey, new_password }` | 204 (the passkey variant lets a passkey-only user set a first password) |
| `POST me/verify-email` | – | 202 `{ sent: true }`: a 24 h verification link to the current address (409 already verified, 400 email not configured) |
| `POST me/email` | `{ new_email, password }` or `{ new_email, passkey }` | 202 `{ sent: true }`: a 24 h link to the NEW address; the change applies when it is opened (`POST /api/authn/email/verify`, 409 if the address is taken by then) and notifies the old address if it was verified. Always 202 for a well-formed request with a valid re-authentication — also for an address that is taken (no probing for accounts). 403 wrong re-authentication, 400 invalid / same as current / not configured |
| `GET me/notifications` | – | `{ channels: { email, telegram }, items: [{ event, email, telegram }] }` (`channels.telegram` only while a chat is linked) — all six events (`password_changed`, `mfa_changed`, `email_changed`, `new_sign_in`, `token_reuse`, `identity_linked`), default on |
| `PUT me/notifications` | `{ items: [{ event, email, telegram? }] }` (any subset; unknown / repeated event → 400) | same as `GET` |
| `POST me/reauth/options` | `{}` | `{ publicKey: PublicKeyCredentialRequestOptionsJSON }` for the user's passkeys (409 if none) |
| `GET me/passkeys` | – | `{ items: Passkey[] }` |
| `POST me/passkeys/options` | Reauth | `{ publicKey: PublicKeyCredentialCreationOptionsJSON }` (`excludeCredentials` = the user's passkeys); 409 when the user already has 20 (checked before re-auth and before the browser creates anything) |
| `POST me/passkeys` | `{ credential: RegistrationJSON, name? }` | 201 `Passkey` (400 rejected / no live challenge, 409 already registered or 20 reached) |
| `PATCH me/passkeys/{id}` | `{ name }` | `Passkey` (1–64 characters) |
| `DELETE me/passkeys/{id}` | Reauth | 204; 409 when it is the last sign-in method (no password, no linked identity, last passkey) |
| `POST me/totp` | Reauth | `{ secret, otpauth_uri, digits: 6, period: 30, algorithm: "SHA1" }` |
| `POST me/totp/confirm` | `{ code }` | `{ recovery_codes: [10 × "xxxx-xxxx-xxxx"] }` |
| `DELETE me/totp` | Reauth | 204: TOTP and recovery codes removed |
| `POST me/recovery-codes` | Reauth | `{ recovery_codes }` (replaces all) |
| `GET me/telegram` | – | `{ linked, username, linked_at }` (SPA polls it while linking); 404 without a Telegram bot |
| `POST me/telegram/link` | Reauth | `{ url: "https://t.me/<bot>?start=<code>", expires_at }`: a single-use 10-min deep link (replaces an unused one; linking again moves the user to the new chat). The link happens when the user presses Start in the bot |
| `DELETE me/telegram` | Reauth | 204: chat unlinked (also pending codes); 404 when not linked |
| `GET me/identities` | – | `{ items: Identity[] (without subject), available: [{ id, name }] }` — `available` = enabled identity providers not linked yet |
| `POST me/identities/{idp_id}/link` | Reauth | `{ redirect }` to the provider (navigate there); sets the tx-binding cookie the callback checks. 404 unknown / disabled provider, 409 already linked to one of its accounts, 503 provider unreachable |
| `DELETE me/identities/{id}` | Reauth | 204; 409 when it is the last sign-in method |
| `GET me/sessions` | – | `{ items: Session[] }` (`current` marks the token's session) |
| `DELETE me/sessions/{id}` | – | 204 |
| `POST me/sessions/revoke-all` | – | 204 |
| `GET me/consents` | – | `{ items: [ConsentGrant + client: {id, client_id, display_name}, resource: {…}] }` (own grants only) |
| `DELETE me/consents/{id}` | – | 204 |

- **Security info changes need re-authentication** (`POST me/totp`,
  `DELETE me/totp`, `POST me/recovery-codes`, `POST me/passkeys/options`,
  `DELETE me/passkeys/{id}`, `POST me/telegram/link`, `DELETE me/telegram`,
  `POST me/identities/{idp}/link`, `DELETE me/identities/{id}`; also `change-password` and `email`): a stolen
  access token alone can't add, remove or read out a factor. **Reauth** =
  `{ "password": "…" }` OR `{ "passkey": AssertionJSON }` answering a
  `POST me/reauth/options` challenge (single use, 5 min) — exactly one (else
  400), so a user who has only passkeys can manage the account. Wrong → 403;
  attempts count against the same per-account rate limit as sign-in (429 +
  `Retry-After`). A passkey whose counter went backwards is refused and
  audited (`user.mfa.passkey_sign_count_regression`).
- <a id="linked-identities"></a>**Linked identities** ([../federation.md](../federation.md)):
  linking re-authenticates, then the browser makes the upstream round trip;
  the callback (only in the browser that started it) links the verified
  identity and returns to `/myaccount/security?federation=linked` or
  `?federation_error=upstream_failed|already_linked|account_disabled|session_ended`
  (`session_ended`: the delegated session that started the link was
  signed out or revoked before the callback). An
  identity belongs to one user, a user has one per provider. Linking sends
  the `identity_linked` notice and is audited `user.identity_link`
  (`via: me`); unlinking `user.identity_unlink`. A user whose only sign-in
  method is a linked identity can't re-authenticate (no password or passkey);
  an admin password reset gives them one.
- `Passkey` = `{ id, name, created_at, last_used_at, backup_eligible,
  backup_state, transports, aaguid }`. Registration is two calls: the
  options (after re-auth) carry a `register` challenge, `POST me/passkeys`
  answers it. Adding or removing a passkey sends the "MFA changed" notice.
  Shapes in [authn.md](authn.md#passkeys), policy in [../passkeys.md](../passkeys.md).
- **Telegram** ([../telegram.md](../telegram.md)): a linked chat is a second
  factor (sign-in asks for a code sent there) and receives the notices whose
  `telegram` toggle is on. Linking and unlinking (here or by `/stop` in the
  bot) send the "MFA changed" notice and are audited `user.mfa.telegram_link`
  / `_unlink` (`via` bot \| me); an admin's Reset MFA unlinks too, recorded as
  `user.mfa_reset` with `telegram_unlinked`.
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
