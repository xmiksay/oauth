# Consent and assignment required

Part of the [architecture](architecture.md): the two gates between a signed-in
principal and tokens for an app. Assignment is checked first, so an unassigned
user is never asked to consent. Settings: `admin_consent_required` on a scope,
`assignment_required` on an app ([api/applications.md](api/applications.md)).

## Consent

A delegated scope is covered by a user grant or a tenant-wide admin grant
(`consent_grants.user_id IS NULL`) for (client, resource). Missing scopes
with `admin_consent_required` → `access_denied` (interactive) /
`consent_required` (`prompt=none`), description "admin approval required for:
…" — users are never offered them. Other missing scopes go to the consent
step; approval merges them into the user's grant. `prompt=consent` asks again
for all user-consentable scopes. Built-in clients skip consent. OIDC scopes
need no consent (grants are keyed by a resource app).

## Assignment required

An app with `assignment_required` (default off; not settable on built-in
apps) only serves principals holding one of its roles (`oidc::assignment`):
a user needs one of its user roles assigned directly or through a group, an
app one of its application permissions — exactly the roles that would
become the `roles` claim. It applies to the app as **client** (users signing
in to it) and as **resource** (delegated tokens for it need the user's
assignment, app-only tokens the calling app's). Checked at authorize after
sign-in and before consent, and again when consent is approved (an
unassigned user is never asked to consent, nor stores a grant) →
`access_denied` redirect (only after the redirect URI matched; also with
`prompt=none`), on code redemption and on every refresh (only the resource
actually minted for: a multi-resource refresh checks the new resource
(`mrrt`), a refresh narrowed to OIDC scopes skips it) and on
`client_credentials` → `invalid_grant`. A refused refresh doesn't rotate
the token, so a restored assignment works again. In the login flow the check runs once
sign-in is complete, after any MFA step the policy demands (a password
alone reveals nothing about assignments) and after a federated sign-in
applied its group mappings (a mapped group's role counts; at stage `link`
the mappings apply only on completion, so they don't count for that first
sign-in). An app requiring
assignment with no roles admits nobody. Access tokens already issued stay
valid until they expire. Every grant issuing delegated tokens goes through
`oidc::token::ensure_assigned` (the device-code grant included; its
browser side refuses at code entry or after sign-in like authorize and
denies the device request, `reason` `not_assigned`). The
portal and `AppLauncher` list only built-in areas (which can't require
assignment), so there is nothing to hide; a future list of registered apps
must filter with `oidc::assignment::user_may_use`.
