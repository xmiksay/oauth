# Refresh tokens

Part of the [architecture](architecture.md): the `refresh_token` grant
(`oidc::refresh_grant`) and multi-resource refresh (`oidc::mrrt`).

## Rotation

Only for grants that included `offline_access` (public clients too — rotation
protects them). Every use rotates; the new token inherits the family's
absolute `expires_at` (the client's `refresh_token_ttl_secs` from the first
issue). Presenting a rotated token revokes the whole family. `scope` may
narrow the access token; the new refresh token keeps the original scopes and
resource. Resource scopes beyond the family's grant — of another resource, or
more of the grant's own — go through [multi-resource
refresh](#multi-resource-refresh); OIDC scopes never widen. Scope / user /
consent / MFA checks happen before rotation (a rejected request rolls back),
so a rejected request doesn't burn it. Rotation and issuance share one DB
transaction, so of two concurrent redemptions the loser sees the token rotated
and revokes the family including the winner's new token. A rotation refuses (→
reuse path) when any token of its family is revoked, and family revocation
repeats its UPDATE until nothing changes (the first pass waits on the lock of
a rotation in flight; the next sees its new token), so a revocation racing a
rotation (replay, RFC 7009 revoke, code replay) never leaves a live token.
Introspection reports a refresh token inactive if anything in its family is
revoked.

## Multi-resource refresh

Entra-style: one refresh token mints access tokens for more than one resource.
`scope` naming another resource than the grant's (or values of its own
resource the family's grant lacks) (still one resource per request, so every
access token has one `aud`) mints an access token for it when every requested
value (`.default` = the client's required permissions on it, as at authorize)
is covered **now** by the user's or the tenant-wide admin consent for this
client (built-in clients: pre-consented), and the token's sign-in `amr` is
multi-factor if the tenant, the client or that resource requires MFA;
otherwise `invalid_grant` ("sign in interactively"). Unknown resources (incl.
other tenants' apps), values it doesn't expose and an empty `.default` →
`invalid_scope`; OIDC scopes still can't exceed the grant. Nothing about the
other resource is stored: the rotated token keeps the family's grant, so a
withdrawn consent stops the next redemption (and its revocation hits the
opaque tokens it produced, which carry that resource). The consent rows are
read `FOR SHARE` in the issuing transaction, so a withdrawal racing a
redemption waits for it and then revokes the token it issued.

## Revocation by directory changes

Withdrawing a consent grant revokes the client's refresh families and opaque
access tokens for the resource (one user, or everyone for an admin grant);
deleting a scope revokes the families holding it and every opaque access token
for the resource carrying it (incl. ones minted by a multi-resource refresh
from another resource's family), and refresh never re-mints a scope the
resource no longer exposes.
