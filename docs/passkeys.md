# Passkeys (WebAuthn)

Part of the [architecture](architecture.md); endpoint contracts in
[api/authn.md](api/authn.md) (sign-in, invitations), [api/me.md](api/me.md)
(My Account) and [api/management.md](api/management.md) (admin).

## Verifier (`webauthn`)

Our own WebAuthn Level 3 relying-party verifier, pure (no I/O): AWS-LC
(`aws-lc-rs`) for signatures and SHA-256, `ciborium` for CBOR. No
webauthn-rs, no OpenSSL, no RustCrypto `p256` / `rsa`.

| Module | Does |
|---|---|
| `cbor` | Decoding with a nesting cap (16) and exact-length / prefix modes; maps used for lookups are size-capped (32 entries) and refused on duplicate keys |
| `authdata` | rpIdHash, flags UP / UV / BE / BS / AT / ED, signCount, attested credential data (credential id 1–1023 bytes, COSE key), extensions; trailing bytes refused |
| `cose` | ES256 (P-256), EdDSA (Ed25519), RS256 (RSA PKCS#1 v1.5, 2048–8192 bits) → AWS-LC `ParsedPublicKey` (the key is validated, e.g. the EC point on the curve, when parsed) |
| `client_data` | `type`, `challenge`, `origin` = the tenant origin exactly, `crossOrigin` / `topOrigin` refused |
| `register` | `attestation: "none"`: `fmt` and `attStmt` are parsed for shape only and never trusted (any format accepted) |
| `assert` | Signature over `authenticatorData ‖ SHA-256(clientDataJSON)`, counter rule, backup-eligibility unchanged |

Policy: **RP ID = the tenant host without port** (`acme.id.example.com`,
dev `acme.localhost`) so a passkey belongs to one tenant; the origin must
equal `config.tenant_origin(slug)` byte for byte. User presence and user
verification are both required (`userVerification: "required"`). Every
untrusted input is size-bounded before parsing (client data 8 KiB,
attestation object 16 KiB, authenticator data 4 KiB, signature 1 KiB),
and parsing never panics (a sweep of truncations and mutations of the
WebAuthn §16 test vectors is a unit test).

**Sign counter**: once either the stored or the received counter is
non-zero, the received one must be larger; otherwise the attempt is
refused and audited (`sign_in` failure `reason: sign_count_regression`, or
`user.mfa.passkey_sign_count_regression` for a re-authentication). It is
checked only after the signature, and re-checked in the UPDATE that stores
it, so of two racing assertions with one counter value only one wins.
Synced passkeys that always report 0 stay valid.

## State (`passkey`)

| Table | Notes |
|---|---|
| `webauthn_credentials` | `credential_id` (unique per tenant), `public_key` (the COSE_Key as sent), `alg` ∈ {-7, -8, -257}, `sign_count`, `rp_id`, `transports[]`, `aaguid`, `name` (1–64), `backup_eligible`, `backup_state` (CHECK: BS ⇒ BE), `last_used_at`; FK `(tenant_id, user_id)` |
| `webauthn_challenges` | SHA-256 of the challenge (256 random bits, base64url), `purpose` register\|login\|reauth, `user_id` (register / reauth; set for login at the MFA step), `tx_id` (login only; FK `(tenant_id, tx_id)` → `login_transactions`), `expires_at` = 5 min; swept |
| `users.webauthn_handle` | 32 random bytes, the WebAuthn user handle (the user id is never exposed); created at the first registration by a conditional UPDATE (no migration backfill, no pgcrypto) |

A challenge is **single use**: it is consumed by one `DELETE … RETURNING`
matching tenant, hash, purpose, expiry and scope (the login transaction,
or the user), on its own statement before anything else is verified — a
failed attempt burns it. Issuing a new challenge replaces the scope's
previous one (one per login transaction, one per user and purpose), which
also bounds the rows a client can create.

## Flows

- **Passwordless sign-in** (login step `password`): options without
  `allowCredentials` (discoverable credentials; the SPA also uses
  `mediation: "conditional"` autofill). The credential is looked up by id
  within the tenant and its owner's handle must equal the response's
  `userHandle`. `amr = ["hwk"|"swk", "user", "mfa"]` (`swk` when
  backup-eligible). MFA and a forced password change are skipped — a
  user-verifying passkey is multi-factor on its own.
- **Second factor** (step `mfa`, reached after the password when the user
  has a confirmed TOTP **or** a passkey): the credential must belong to the
  transaction's user; `amr = ["pwd", "hwk"|"swk", "mfa"]`. No new login
  stage (and no CHECK migration).
- Rate limits and audit as for the other factors: IP and account buckets
  (the account of the credential, or of the transaction), every failure a
  `sign_in` failure with `factor: "passkey"` and a fixed `reason`
  (`invalid_challenge`, `unknown_credential`, `foreign_credential`,
  `wrong_origin`, `wrong_rp_id`, `user_not_verified`, `bad_signature`, …).
  The client only ever sees `invalid_credentials`.
- **My Account**: list, rename; register and remove after
  **re-authentication** = the current password OR a passkey assertion for a
  `reauth` challenge, so passkey-only users can manage their account
  (also accepted for TOTP, recovery codes, email change and
  change-password — the passkey variant sets a first password). Max 20
  passkeys per user, refused (409) already at the creation options: a
  credential the browser creates for options that are then rejected is
  orphaned on the authenticator. For the same reason the SPA drops the
  options after any server answer and only keeps them when the browser
  dialog was dismissed. COSE keys over 2048 bytes are refused (`Malformed`).
- **Last sign-in method**: a user without a password can't remove their
  last passkey (self-service or admin), under the user's row lock.
- **Invitations**: `/login/invite` can create a passkey instead of a
  password. Same token rules (`still_valid`, single use, rollback keeps it
  unused); it marks the address verified and voids the user's other
  invitations. An invitation is spent for a user holding a passkey
  (password acceptance refused, resend 409; an admin email change sends a
  verification link instead of a new invitation).
- **Admin**: the user detail lists passkeys and can remove one. **Reset
  MFA** removes TOTP, recovery codes and passkeys — except for a user
  without a password who has passkeys: then it is refused (409), because it
  would lock them out. The recovery is explicit: `reset-password` (a
  one-time password the user must change), then `reset-mfa`.

Audit: `user.mfa.passkey_register` / `_rename` / `_remove` (details:
`passkey_id`, `name`, `via` me\|admin\|invite), `user.mfa_reset`
(`passkeys_removed`). Adding and removing a passkey sends the "MFA changed"
notice (`notify::event`).
