# Upstream identity providers (federation)

A tenant can let its users sign in through upstream OpenID Connect
providers (and GitHub, which speaks plain OAuth 2.0). We are the relying
party there: authorization code flow with PKCE S256, `state`, `nonce` and
`response_mode=query`; client auth `client_secret_post` or
`client_secret_basic`. Code: `federation/` (protocol; `kinds` = the
Google / Entra rules, `github` = the GitHub adapter), `authn::federation*` (login flow), `api::identity_providers`,
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

## Presets

`kind` picks the provider type at creation (it can't change later: it
decides what a subject is). The admin UI's preset picker fills in the
well-known URLs; every URL stays editable (sovereign clouds, GitHub
Enterprise Server) and passes the same URL policy.

| `kind` | Configuration | Extra checks |
|---|---|---|
| `oidc` | as above | — |
| `google` | issuer `https://accounts.google.com` (default), optional `hosted_domain` (Google Workspace domain) | With `hosted_domain`: the authorization request carries `hd=` (it only narrows Google's account chooser) and the ID token's `hd` claim must equal it (case-insensitive), else `id_token_hd`. Google's documented scheme-less `iss` `accounts.google.com` is accepted for that issuer. |
| `entra` | single-tenant: issuer `https://login.microsoftonline.com/{tid}/v2.0`; multi-tenant: issuer `https://login.microsoftonline.com/{tenantid}/v2.0` (the literal placeholder, as Microsoft's discovery document writes it) + `discovery_url` `…/organizations/v2.0/.well-known/openid-configuration` (or `common`), optional `allowed_tenants` | The token's `tid` must be a GUID, else `id_token_tid`. Multi-tenant: `iss` must be the template with a GUID in place of `{tenantid}`, and that GUID must be the token's `tid` (`id_token_tid`) — a tenant can't sign tokens for another; with `allowed_tenants`, `tid` must be listed (`tenant_not_allowed`). `xms_edov: true` (Entra's optional claim: the email domain is verified by its owner tenant) counts as `email_verified`. |
| `github` | issuer = a bare web origin in canonical form (`https://github.com`, default, or a GHES origin; a path, an upper-case host or a default port such as `:443` is refused, since github.com is recognised by string to pick `api.github.com`); scopes `read:user user:email`; a client secret is required while enabled | No OpenID: authorize `{issuer}/login/oauth/authorize`, token `{issuer}/login/oauth/access_token`, API `https://api.github.com` (GHES: `{issuer}/api/v3`). The access token reads `GET /user` (subject = the numeric `id`, name = `name` or `login`) and `GET /user/emails`: only the **verified primary** address is used; a 403 / 404 there (no `user:email` grant) means no email, any other error fails the sign-in (`github_emails`). No ID token, so no `amr` (upstream MFA is never trusted) and no `auth_time`: an authorization request with `prompt=login` / `max_age` can't use GitHub (`reauth_unsupported`, refused before leaving). |

Entra sends no `email_verified`, so without `xms_edov` (configure it as an
optional claim of the app registration) a JIT provider would refuse every
user with `upstream_no_email`. Entra's `sub` is pairwise per application and
assigned by Microsoft; it is the subject as for any OIDC provider.

### Trusting the upstream email

`trust_upstream_email` (default `false`, GlobalAdmin; not for `github`)
treats the ID token's `email` as verified even without `email_verified`
(or `xms_edov`). **Risk:** JIT then provisions an account under whatever
address the provider reports. Enable it only for a provider whose
administrators control the addresses (an organisation's own directory),
ideally together with `email_domains` so JIT accepts only your domains —
never for a provider where users type their own email (consumer
accounts). On a multi-tenant Entra provider (anyone can create a tenant
and set any unverified `email`) it is refused (400) unless
`allowed_tenants` names the tenants to trust. It never links an existing account by
email: an address that belongs to a local user is still `account_exists`.

Issuers and discovery URLs must be `https://`. Plain `http://` is accepted
only for loopback hosts (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`)
and only when `PUBLIC_URL` is itself `http://` (local development).

## Policies (first sign-in of an unknown identity)

| Policy | Unknown `(issuer, sub)` |
|---|---|
| `link_only` (default) | The login page asks the user to sign in with their existing account (password or passkey, then MFA as usual); completing that sign-in links the identity. |
| `jit` | A user is created with the upstream **verified** email (`email_verified`; for Entra `xms_edov`; any email with `trust_upstream_email`; GitHub's verified primary), `email_verified = true`, no password, the upstream name. Refused without a verified email (`upstream_no_email`), when the IdP lists `email_domains` and the address is of another domain (`email_domain_not_allowed`), and when a local user already has that email (`account_exists`). |
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

A repoint also bumps the provider's `generation`, and so does any change of
`allowed_tenants` or `hosted_domain` (without unlinking anyone): a callback
verified against a wider list must not land, or a de-listed tenant would
still get mapped groups. A change that narrows them (a tenant removed or
a first one pinned; a `hosted_domain` set or changed) also drops every
membership the provider's mappings kept (see Group mappings): identities
don't record the upstream `tid` / `hd`, so the de-listed ones can't be told
apart, and their users can no longer sign in to have them re-synced;
still-allowed users get theirs back on their next sign-in. Widening (a
tenant added, the list cleared, the domain removed) keeps them; the admin
UI asks before a narrowing save. Round trips and parked
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
- **ID token** (all kinds but `github`): signature with a key from the provider's JWKS; the algorithm
  comes from the key (RSA → RS256, P-256 → ES256, Ed25519 → EdDSA; a key
  announcing another `alg` or `use: enc` verifies nothing), so `none` / HS*
  tokens can't pass. Claims: `iss` exact (Entra multi-tenant: the
  template filled with the token's own `tid`, see [Presets](#presets)), `aud` contains our client id,
  `azp` = our client id when present and required with several audiences,
  `exp` / `iat` / `nbf` with 60 s skew, `nonce`, `sub` 1–255 characters.
  RFC 9207: an `iss` callback parameter must match the issuer the same way.
- **Discovery** cached 1 h per provider; its `issuer` must equal the
  configured one and its endpoints pass the same URL policy; a failed
  discovery is remembered for 30 s. **JWKS** cached 1 h; an unknown `kid`
  refetches it, at most once a minute. Starting an upstream sign-in is
  limited to 30 / 5 min per IP.
- **Outbound HTTP** (shared `http` client): rustls on AWS-LC, webpki roots,
  no redirects, no proxy, 10 s / 5 s timeouts, responses capped at 256 KiB.
  The provider is contacted only by our server (discovery, JWKS, token
  endpoint; GitHub's `/user` and `/user/emails` with the access token,
  which is then dropped); the authorization request is a browser redirect.
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

## Group mappings

An identity provider can map upstream claim values to local groups
(admin center → Identity providers → the provider → Group mappings;
GlobalAdmin; API [api/identity_providers.md](api/identity_providers.md)).
A mapping is `claim` (a top-level ID token claim, e.g. `groups`, `roles`)
+ `value` + a group of the tenant; several mappings may grant one group,
at most 100 per provider.

A mapped claim is only as trustworthy as the tenants allowed to sign the
token. On a multi-tenant Entra provider (`{tenantid}` issuer) any Entra
tenant can sign in, and its own admins control `wids` (directory role
template ids, e.g. Global Administrator `62e90394-…`, the same in every
tenant), `roles` of a multi-tenant app (any consenting tenant assigns them
in its own service principal) and on-prem group names. So such a provider
needs `allowed_tenants` before it can have mappings: creating a mapping
without it is a 400, and so is a PATCH that clears `allowed_tenants` or
switches the issuer to a templated one while mappings exist. Mappings
stored before this rule, on a provider that still accepts every tenant,
decide nothing at sign-in (the memberships they kept stay as they are).
Even with tenants pinned, prefer mapping `groups` by object id over
`wids` / `roles` / group names: an object id names one group of one
tenant.

On every federated sign-in — of a linked identity, at JIT creation, and
when stage `link` links a parked identity and completes the sign-in — the
user's memberships follow the token: the user joins each group whose
mapping's value appears in its claim (exact, case-sensitive match; the
claim may be a string or an array of strings) and leaves each group this
provider's mappings put them in and no longer grant. This runs in the
sign-in's writing transaction, which holds the provider row `FOR SHARE`
at the verified generation; mapping writes take it `FOR UPDATE`, so a
sign-in sees the mappings as they were before or after a change, never
half of it. Every membership added or removed is audited
(`group.member_add` / `group.member_remove`, user → group, `via:
"federation"`, `idp_id`).

For a linked identity and at JIT the mappings apply as soon as the
upstream identity is resolved, before any local stage (MFA, password
change) that follows: the upstream is authoritative for what its claims
say, whether or not this sign-in ends in a local session, and the next
sign-in re-decides anyway. A sign-in abandoned at a local stage keeps
the membership changes. (Stage `link` applies them when it completes,
since the identity isn't linked before.)

Each membership records its source: `manual` (an administrator added it)
and `idp_id` (this provider's mappings keep it). A sign-in only removes
rows its own provider keeps, so manual memberships and those of other
providers are never touched:

- A mapping finding a manual membership no provider keeps marks it as
  kept by this provider too (no audit event — the membership doesn't
  change), so the source reads the same whichever came first; when the
  claim value goes, only the mark goes. Another provider's membership is
  left as it is.
- A membership is kept by one provider at a time. When two providers map
  the same group and the keeping one lets go (its claim value goes), the
  membership goes; the other provider adds it again at its own next
  sign-in while it still grants the group.
- An administrator adding a user to a group a mapping put them in makes
  the row manual as well; when the claim value goes, only the mapping mark
  goes and the membership stays.
- An administrator removing a mapped membership removes it; the mapping
  adds it again at the next sign-in while the claim value is there.

Claim values are bounded before use: each 1–256 bytes without control
characters (others skipped), and only the `(claim, value)` pairs the
provider's mappings name are looked for — nothing else of the token is
kept, so a parked identity stays small. A claim the token doesn't state
in full decides nothing: an array of more than 256 entries (Entra caps
its `groups` claim at 200), or a claim named in `_claim_names` (Entra's
group overage, pointing at Graph, which is not followed). The
memberships its mappings grant are then neither added nor removed; a
missing claim, in contrast, carries none of its values. A `github` provider
has no ID token, so its mappings never decide anything.

The pairs are taken from the mappings when the token is verified,
before the writing transaction; a parked identity keeps which pairs were
decided and which the token carried until stage `link` completes. If the
mappings change in between, a mapping whose pair wasn't decided can't
be: the membership of its group is neither added nor removed by this
sign-in (the next one decides), so a mapping moved to another claim or
value never drops a membership it still grants.

Not a sign-in, so no mapping is applied: linking an identity from My
Account (the next sign-in through the provider applies them). A new
mapping applies from each user's next sign-in. Deleting a
mapping removes the memberships it kept at once, unless another mapping
of the provider grants the same group. A **repoint**, narrowing
`allowed_tenants` / `hosted_domain`, deleting the
provider and unlinking a user's identity drop the memberships the
provider's mappings kept (of everyone / of that user; manual ones lose
just the mark), counted as `memberships_removed` in the audit event, and
each removed membership is audited by itself as well (`group.member_remove`
by the administrator, `user_id`, `idp_id`, `via: "federation"`).
Deleting a group removes its mappings.

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
| `identity_providers` | `name` unique per tenant, `kind` oidc\|google\|entra\|github (fixed at creation), `hosted_domain` (google only), `allowed_tenants[]` (entra only), `trust_upstream_email`, `enabled`, `visible`, `issuer`, `discovery_url`, `client_id`, `client_secret_sealed`, `client_auth` post\|basic, `scopes[]`, `policy` jit\|link_only\|deny, `trust_upstream_mfa`, `mfa_acr`, `email_domains[]`, `generation` (bumped by a repoint or an `allowed_tenants` / `hosted_domain` change) |
| `user_identities` | (tenant, IdP, `subject`) unique, (tenant, user, IdP) unique, `email` (as last seen upstream, informational), `linked_at`, `last_used_at`; cascades with the user or the IdP |
| `idp_group_mappings` | `(tenant, IdP, claim, value, group)` unique, composite FKs to the IdP and the group (cascade); `claim` `^[A-Za-z0-9_.:/-]{1,64}$`, `value` 1–256 bytes |
| `group_members.manual` / `.idp_id` | source of a membership: added by an administrator and/or kept by that IdP's mappings (`CHECK (manual OR idp_id IS NOT NULL)`, composite FK to the IdP `ON DELETE SET NULL (idp_id)`) |
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
