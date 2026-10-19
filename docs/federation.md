# Upstream identity providers (federation)

A tenant can let its users sign in through upstream OpenID Connect
providers. We are the relying party there: authorization code flow with
PKCE S256, `state`, `nonce` and `response_mode=query`; client auth
`client_secret_post` or `client_secret_basic`. Code: `federation/`
(protocol), `authn::federation*` (login flow), `api::identity_providers`,
`api::me_identities`, `api::user_identities`. API contracts:
[api/authn.md](api/authn.md#federation), [api/identity_providers.md](api/identity_providers.md),
[api/me.md](api/me.md#linked-identities).

## Setup

1. At the provider, register a confidential web client with the redirect
   URI `https://{slug}.{PUBLIC_URL host}/federation/callback` (the tenant's
   canonical host; the IdP's `redirect_uri` field in the API shows it).
2. In the admin center → Identity providers (GlobalAdmin), create it:
   `issuer` (exactly as the provider's discovery document states it),
   `client_id`, `client_secret`, `client_auth`, `scopes` (must contain
   `openid`; default `openid email profile`), optionally `discovery_url`
   (default `{issuer}/.well-known/openid-configuration`), `policy`,
   `trust_upstream_mfa` / `mfa_acr`, `email_domains`, `visible`, `enabled`.
3. Visible, enabled providers appear as "Sign in with …" buttons. Hidden
   ones are reached through home-realm discovery: an email domain listed
   in `email_domains` (unique per tenant), the authorize parameter
   `domain_hint=contoso.com`, or `idp={idp id}` (the SPA then goes straight
   to the provider, except right after a failed attempt).

Issuers and discovery URLs must be `https://`. Plain `http://` is accepted
only for loopback hosts (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`)
and only when `PUBLIC_URL` is itself `http://` (local development).

## Policies (first sign-in of an unknown identity)

| Policy | Unknown `(issuer, sub)` |
|---|---|
| `link_only` (default) | The login page asks the user to sign in with their existing account (password or passkey, then MFA as usual); completing that sign-in links the identity. |
| `jit` | A user is created with the upstream **verified** email (`email_verified`), `email_verified = true`, no password, the upstream name. Refused without a verified email (`upstream_no_email`), when the IdP lists `email_domains` and the address is of another domain (`email_domain_not_allowed`), and when a local user already has that email (`account_exists`). |
| `deny` | Refused (`not_linked`); only identities linked beforehand sign in. |

Accounts are **never linked by email** — linking always needs the local
account's own credentials (in the login flow at stage `link`, or from My
Account after re-authentication). A user links at most one identity per
provider, an identity belongs to one user. At stage `link` a local account
that already has an identity at the provider is refused right away
(`409 already_linked`); a provider disabled, deleted or switched away from
`link_only` while an identity is parked releases the transaction back to
the password step (`notice: link_unavailable`, or `409 link_unavailable` on
submission). If that happens only after the local password, while the
user is at MFA, password change or consent, the sign-in still completes —
the user did authenticate locally — but without the link; the skipped link
is audited as a failed `user.identity_link` (`reason` `link_unavailable` /
`already_linked`) and the user can link again. A My Account link completes
only while the delegated session that started it is live and the user's —
checked when the callback arrives and again, with the session row locked,
in the transaction that writes the link (else
`federation_error=session_ended`).

**Repointing a provider** — changing its `issuer`, `client_id` or
`discovery_url` — unlinks everyone, drops its round trips in flight and
sends logins parked on it back to the password step, in the same
transaction (audit `identities_removed`): another provider or client means
other subjects, and keeping the links would hand accounts to whoever the
new configuration names that way. Moving the `issuer` or `discovery_url`
also removes the stored client secret unless the same PATCH sets a new one,
so a repoint can't send the old provider's secret elsewhere. The API
reports `linked_users`; the admin UI asks before such a change.

A repoint also bumps the provider's `generation`. Round trips and parked
identities remember the generation they were verified at; the writing
transaction of a sign-in, JIT, in-flow link or My Account link locks the
provider row `FOR SHARE` and requires it unchanged (an update locks it
`FOR UPDATE`), so a callback or link racing a repoint fails
(`upstream_failed`, audit `idp_repointed`; `link_unavailable` for a parked
identity) instead of landing on the new configuration.

An upstream sign-in that waits at `mfa`, `change_password` or `consent`
remembers `{idp_id, generation}` on its login transaction (`federated`).
Completing it requires the IdP still enabled and at that generation; if it
was disabled or repointed meanwhile, the transaction is deleted and the
step answers `502 upstream_failed` (audit `idp_disabled` /
`idp_repointed`) — no session.

Lock order: everything that writes on behalf of an upstream identity locks
the IdP row before any login-transaction row. The completing transaction
(`complete::finish`) takes the IdP row `FOR SHARE` first, then claims the
login transaction; a repoint takes it `FOR UPDATE`, then releases parked
logins. The same order on both sides is what keeps them from deadlocking.
Within a repoint the tables go in the sweeper's order: `login_transactions`
(parked logins released) before `federation_states` before
`user_identities`. A My Account link locks IdP → user (`FOR SHARE`) →
session, matching an admin's revoke / disable (user `FOR UPDATE`, then its
sessions).

Accepted race: two administrators editing the same provider. A PATCH from
a page loaded before another admin's repoint can still set a client secret
(a bare secret change is not a repoint), which then goes to the new
configuration. PATCHes apply field by field; there is no optimistic
concurrency check.

Linked identity, enabled user → signed in with `amr: ["fed"]`; a disabled
user is refused (`account_disabled`). On every sign-in the user's display
name follows the upstream `name` (or `given_name family_name`); the email is
set only at JIT time and never overwritten. Upstream tokens are not stored.
Profile claims are bounded before use: names lose control characters (NUL
included) and are cut to 256 characters, an email or `acr` / `amr` value
with control characters or over its length limit is ignored.

**Re-authentication**: `prompt=login` and `max_age` of the local
authorization request are forwarded upstream. The ID token must then carry
an `auth_time` no earlier than the start of the round trip (`prompt=login`)
and within `max_age` (60 s skew), else `upstream_failed`
(`id_token_auth_time`). The local session's `auth_time` is the upstream one
when the token has it.

## MFA

`trust_upstream_mfa = false` (default): local MFA applies whenever the user
has a factor (TOTP, passkey, Telegram) — `amr` then `["fed","otp","mfa"]`
etc. `true`: local MFA is skipped when the ID token's `amr` contains `mfa`,
or its `acr` equals the configured `mfa_acr`; `amr` is then
`["fed","mfa"]`. Trust only providers that enforce MFA themselves.

## Security model

- **Round-trip state** (`federation_states`): `state` = 256 random bits,
  stored as SHA-256; consumed with `DELETE … RETURNING` before anything else
  is checked (single use, also on failure); 10-minute expiry; bound to the
  browser's tx-binding cookie (and, for sign-in, to the login transaction
  at stage `password`). One live state per transaction / per user's link
  attempt. A callback without a live, bound state lands on
  `/login?error=upstream_failed`.
- **PKCE** S256 always; the verifier is sealed (AES-256-GCM, AAD
  `"fedpkce"` ‖ tenant ‖ state id). **Nonce** random, checked in constant time.
- **ID token**: signature with a key from the provider's JWKS; the algorithm
  comes from the key (RSA → RS256, P-256 → ES256, Ed25519 → EdDSA; a key
  announcing another `alg` or `use: enc` verifies nothing), so `none` / HS*
  tokens can't pass. Claims: `iss` exact, `aud` contains our client id,
  `azp` = our client id when present and required with several audiences,
  `exp` / `iat` / `nbf` with 60 s skew, `nonce`, `sub` 1–255 characters.
  RFC 9207: an `iss` callback parameter must equal the issuer.
- **Discovery** cached 1 h per provider; its `issuer` must equal the
  configured one and its endpoints pass the same URL policy; a failed
  discovery is remembered for 30 s. **JWKS** cached 1 h; an unknown `kid`
  refetches it, at most once a minute. Starting an upstream sign-in is
  limited to 30 / 5 min per IP.
- **Outbound HTTP** (shared `http` client): rustls on AWS-LC, webpki roots,
  no redirects, no proxy, 10 s / 5 s timeouts, responses capped at 256 KiB.
  The provider is contacted only by our server (discovery, JWKS, token
  endpoint); the authorization request is a browser redirect.
- **Errors**: the user only sees `upstream_failed` (plus the policy
  refusals above); the fixed reason code (`id_token_nonce`,
  `token_refused`, `unknown_kid`, …) goes to the audit log
  (`sign_in` / `user.identity_link` failures, `details.reason`).
- **Secrets**: the client secret is write-only in the API (`has_secret`),
  sealed with AAD `"idp"` ‖ tenant ‖ IdP id. Codes, tokens, ID tokens,
  states, nonces and verifiers are never logged; the upstream URL (it
  carries the state) neither.
- **Tenant isolation**: composite `(tenant_id, id)` FKs from identities and
  states to providers, users and login transactions; every lookup filters by
  the host's tenant.
- **Public destinations only**: administrators choose the URLs our server
  fetches, so the federation client resolves host names itself and drops
  every non-public answer (loopback, private 10/8 · 172.16/12 · 192.168/16,
  CGNAT 100.64/10, link-local, unique-local fc00::/7, unspecified,
  multicast, broadcast, documentation and reserved ranges, IPv4-mapped /
  NAT64 forms of these); IP literals are checked the same way. Identity
  providers on a private network (on-prem) are therefore not supported in
  production. With an `http://` `PUBLIC_URL` (development) the check is
  off, so loopback providers work.

## Lockout

Disabling or deleting a provider is allowed. `GET identity-providers/{id}`
reports `users_only_via` — users with no password, no passkey and no
identity at another enabled provider — and `linked_users` (everyone linked
through it, unlinked by a repoint); the admin UI warns before disabling,
deleting or repointing. Such users
are recovered with a password reset or an invitation. Unlinking (My Account
or admin) and passkey removal never take a user's last sign-in method
([authn.md](authn.md#last-sign-in-method)); an identity at a disabled
provider doesn't count as one.

## Data

| Table | Notes |
|---|---|
| `identity_providers` | `name` unique per tenant, `kind` oidc, `enabled`, `visible`, `issuer`, `discovery_url`, `client_id`, `client_secret_sealed`, `client_auth` post\|basic, `scopes[]`, `policy` jit\|link_only\|deny, `trust_upstream_mfa`, `mfa_acr`, `email_domains[]`, `generation` (bumped by a repoint) |
| `user_identities` | (tenant, IdP, `subject`) unique, (tenant, user, IdP) unique, `email` (as last seen upstream, informational), `linked_at`, `last_used_at`; cascades with the user or the IdP |
| `federation_states` | `state_hash` (unique), `binding_hash`, `nonce`, `pkce_verifier_sealed`, `purpose` login (with `tx_id`) \| link (with `user_id` and the starting `session_id`), `idp_generation`, `expires_at` = 10 min; swept |

`login_transactions.federated` holds `{idp_id, generation}` of an upstream
sign-in that hasn't completed yet; `login_transactions.pending_identity` holds `{idp_id, generation, subject, email, name}`
while a transaction waits at stage `link`.

## Trying it locally

Point a tenant at a second tenant of the same dev server (every tenant is
an OIDC provider): with `make dev-db`, `make run`, `make web-dev`
(`PUBLIC_URL=http://localhost:5173`), tenants `a` (provider) and `b`
(relying party):

1. In `a`'s admin center, register an app (confidential, redirect URI
   `http://b.localhost:5173/federation/callback`) and create a secret.
2. In `b`'s admin center → Identity providers: issuer
   `http://a.localhost:5173`, that client id and secret, policy as wanted.
3. Open `http://b.localhost:5173/myaccount` and use "Sign in with …".
