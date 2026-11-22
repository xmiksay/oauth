# Management API — identity providers (`/api/v1/identity-providers`)

Part of the [management API](management.md) (authentication, conventions
and audit events there). Read: any directory
role; write: GlobalAdmin (delegated) only; app-only tokens: none.

Upstream providers (OpenID, or GitHub over OAuth 2.0) users can sign in with ([../federation.md](../federation.md)).

```jsonc
// IdentityProvider (the client secret is write-only: only `has_secret`)
{ "id", "name", "kind": "oidc|google|entra|github", "enabled": true, "visible": true, "issuer",
  "discovery_url": null, "client_id", "has_secret": true, "client_auth": "post|basic",
  "scopes": ["openid","email","profile"], "policy": "jit|link_only|deny",
  "trust_upstream_mfa": false, "mfa_acr": null, "email_domains": [],
  "hosted_domain": null, "allowed_tenants": [], "trust_upstream_email": false,
  "redirect_uri": "{origin}/federation/callback", "created_at", "updated_at" }
// … plus on create / GET / PATCH: { "users_only_via": 0, "linked_users": 0 }
```

| Method & path | Body | Response |
|---|---|---|
| `GET identity-providers` *paged* | – | `IdentityProvider`s |
| `POST identity-providers` | `{ kind? ("oidc"), name, issuer, client_id, client_secret?, client_auth? ("post"), discovery_url?, scopes? (openid email profile), policy? ("link_only"), trust_upstream_mfa? (false), mfa_acr?, email_domains? ([]), hosted_domain?, allowed_tenants? ([]), trust_upstream_email? (false), enabled? (true), visible? (true) }` — `issuer` defaults to `https://accounts.google.com` for `google` and `https://github.com` for `github`; `scopes` to `read:user user:email` for `github` | 201 `IdentityProvider` + `users_only_via` + `linked_users` (both 0) |
| `GET identity-providers/{id}` | – | `IdentityProvider` + `users_only_via`: users who can sign in only through it (no password, passkey or identity at another enabled provider) — disabling or deleting it locks them out — + `linked_users`: identities linked through it |
| `PATCH identity-providers/{id}` | any create field (`kind` can't change: 400 unless it is the current one); `client_secret: "…"` replaces the secret, `null` removes it; `discovery_url` / `mfa_acr` / `hosted_domain`: `null` clears. Changing `issuer`, `client_id` or `discovery_url` is a **repoint**: all its identities are unlinked (`linked_users` before the change says how many), its round trips in flight dropped and logins parked on it released; changing `issuer` or `discovery_url` also removes the stored secret unless this PATCH sets a new one (`has_secret` shows it) | `IdentityProvider` + `users_only_via` + `linked_users` |
| `DELETE identity-providers/{id}` | – | 204 (its linked identities and group mappings go with it, and so do the memberships only its mappings kept) |
| `GET identity-providers/{id}/group-mappings` *paged* | – | `IdpGroupMapping`s `{ id, idp_id, claim, value, group_id, group_display_name, created_at }` |
| `POST identity-providers/{id}/group-mappings` | `{ claim, value, group_id }` | 201 `IdpGroupMapping` |
| `DELETE identity-providers/{id}/group-mappings/{mapping_id}` | – | 204; memberships the provider's mappings kept in that group go too, unless another of its mappings still grants the group |

Validation (400): `name` 1–64 characters (409 if taken in the tenant);
`issuer` / `discovery_url` `https://` without query or fragment (`http://`
loopback only with an `http://` `PUBLIC_URL`); `scopes` RFC 6749 tokens,
including `openid` unless `kind` is `github`; `email_domains` DNS names, lower-cased, each claimed by
at most one provider of the tenant (409; writes serialize per tenant);
unknown fields rejected. Per kind ([../federation.md](../federation.md#presets)):
`hosted_domain` (a DNS name, lower-cased) only for `google`; an `issuer`
containing `{tenantid}` only for `entra`, once, in its path, and with a
`discovery_url` (which can't contain it); `allowed_tenants` (GUIDs,
lower-cased, at most 50) only with such a templated issuer, and required
with it for `trust_upstream_email` and while the provider has group
mappings (clearing it, or switching to a templated issuer, with mappings
is a 400); `github`: the `issuer` a bare web
origin (no path, query or credentials), no `discovery_url`, `client_auth`
`post`, `trust_upstream_mfa` and `trust_upstream_email` false, and a stored
`client_secret` whenever it is enabled (GitHub's token endpoint always
requires one: create it with a secret or `enabled: false`; clearing the
secret of, or repointing without a new secret, an enabled one is a 400). `hosted_domain`, `allowed_tenants` and
`trust_upstream_email` are not a repoint: they are checked on every sign-in. Issuers and endpoints must resolve to public
addresses ([../federation.md](../federation.md#security-model)).

Group mappings ([../federation.md](../federation.md#group-mappings)):
`claim` 1–64 of `A-Z a-z 0-9 _ . : / -`, `value` 1–256 bytes without
control characters (kept exactly, matched exactly), `group_id` a group of
the tenant (400 otherwise); a provider with a `{tenantid}` issuer and no
`allowed_tenants` can't have mappings (400: any Entra tenant could grant
itself the groups); the same `(claim, value, group)` twice is 409,
as is a 101st mapping of one provider. Mappings are not edited — delete and
add. A new mapping applies from each user's next sign-in.

Every write locks the provider row; a repoint, or a change of
`allowed_tenants` / `hosted_domain`, bumps its internal generation, so a sign-in or link verified against the old configuration
fails (`upstream_failed`, audit reason `idp_repointed`) instead of landing.
A change that narrows `allowed_tenants` / `hosted_domain` (an entry
removed or a first one pinned; a domain set or changed) also removes every
group membership the provider's mappings kept (manual ones lose just the
mark; counted in `memberships_removed`) without unlinking anyone: users
still allowed get them back on their next sign-in through the provider.
Widening (an entry added, the list cleared, the domain removed) keeps them.
Audit: `identity_provider.create` (`name`, `kind`, `issuer`, `policy`) / `update` (`fields`, `identities_removed`,
`memberships_removed`) / `delete` (`users_only_via`, `memberships_removed`)
/ `group_mapping_add` (`mapping_id`, `claim`, `value`, `group_id`,
`group_display_name`) / `group_mapping_remove` (`mapping_id`, `claim`,
`value`, `group_id`, `memberships_removed`); each membership those remove
is also its own `group.member_remove` (→ group, `user_id`, `idp_id`, `via:
"federation"`).
