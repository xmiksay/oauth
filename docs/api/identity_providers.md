# Management API — identity providers (`/api/v1/identity-providers`)

Part of the [management API](management.md) (authentication, conventions,
the `IdentityProvider` object and audit events there). Read: any directory
role; write: GlobalAdmin (delegated) only; app-only tokens: none.

Upstream OpenID providers users can sign in with ([../federation.md](../federation.md)).

| Method & path | Body | Response |
|---|---|---|
| `GET identity-providers` *paged* | – | `IdentityProvider`s |
| `POST identity-providers` | `{ name, issuer, client_id, client_secret?, client_auth? ("post"), discovery_url?, scopes? (openid email profile), policy? ("link_only"), trust_upstream_mfa? (false), mfa_acr?, email_domains? ([]), enabled? (true), visible? (true) }` | 201 `IdentityProvider` + `users_only_via` + `linked_users` (both 0) |
| `GET identity-providers/{id}` | – | `IdentityProvider` + `users_only_via`: users who can sign in only through it (no password, passkey or identity at another enabled provider) — disabling or deleting it locks them out — + `linked_users`: identities linked through it |
| `PATCH identity-providers/{id}` | any create field; `client_secret: "…"` replaces the secret, `null` removes it; `discovery_url` / `mfa_acr`: `null` clears. Changing `issuer`, `client_id` or `discovery_url` is a **repoint**: all its identities are unlinked (`linked_users` before the change says how many), its round trips in flight dropped and logins parked on it released; changing `issuer` or `discovery_url` also removes the stored secret unless this PATCH sets a new one (`has_secret` shows it) | `IdentityProvider` + `users_only_via` + `linked_users` |
| `DELETE identity-providers/{id}` | – | 204 (its linked identities and group mappings go with it, and so do the memberships only its mappings kept) |
| `GET identity-providers/{id}/group-mappings` *paged* | – | `IdpGroupMapping`s `{ id, idp_id, claim, value, group_id, group_display_name, created_at }` |
| `POST identity-providers/{id}/group-mappings` | `{ claim, value, group_id }` | 201 `IdpGroupMapping` |
| `DELETE identity-providers/{id}/group-mappings/{mapping_id}` | – | 204; memberships the provider's mappings kept in that group go too, unless another of its mappings still grants the group |

Validation (400): `name` 1–64 characters (409 if taken in the tenant);
`issuer` / `discovery_url` `https://` without query or fragment (`http://`
loopback only with an `http://` `PUBLIC_URL`); `scopes` RFC 6749 tokens
including `openid`; `email_domains` DNS names, lower-cased, each claimed by
at most one provider of the tenant (409; writes serialize per tenant);
unknown fields rejected. Issuers and endpoints must resolve to public
addresses ([../federation.md](../federation.md#security-model)).

Group mappings ([../federation.md](../federation.md#group-mappings)):
`claim` 1–64 of `A-Z a-z 0-9 _ . : / -`, `value` 1–256 bytes without
control characters (kept exactly, matched exactly), `group_id` a group of
the tenant (400 otherwise); the same `(claim, value, group)` twice is 409,
as is a 101st mapping of one provider. Mappings are not edited — delete and
add. A new mapping applies from each user's next sign-in.

Every write locks the provider row; a repoint bumps its internal
generation, so a sign-in or link verified against the old configuration
fails (`upstream_failed`, audit reason `idp_repointed`) instead of landing.
Audit: `identity_provider.create` / `update` (`fields`, `identities_removed`,
`memberships_removed`) / `delete` (`users_only_via`, `memberships_removed`)
/ `group_mapping_add` (`mapping_id`, `claim`, `value`, `group_id`,
`group_display_name`) / `group_mapping_remove` (`mapping_id`, `claim`,
`value`, `group_id`, `memberships_removed`).
