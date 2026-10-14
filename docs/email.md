# Email

Part of the [architecture](architecture.md); endpoint contracts in
[api/authn.md](api/authn.md) (public link endpoints) and
[api/me.md](api/me.md) / [api/management.md](api/management.md).

Optional (`SMTP_URL` + `SMTP_FROM`; unset → `features.password_reset` /
`features.email` are false and the endpoints 404 / 400). Actions never send:
they queue an `outbox` row on their own transaction (rollback = no mail) and
the `outbox` job delivers it. From = `"{tenant display name}" <SMTP_FROM>`,
EHLO name = the `PUBLIC_URL` host.

## Transport

Mail carries reset and invitation links, so `SMTP_URL` must be encrypted and
not downgradable: `smtps://…` (implicit TLS) or `smtp://…?tls=required`
(STARTTLS). Plain `smtp://` or `?tls=opportunistic` is accepted only to a
loopback host (`localhost`, `127.0.0.0/8`, `::1` — a dev sink like Mailpit),
and credentials only over required TLS; anything else fails startup. TLS is
rustls on AWS-LC (installed as the process-wide rustls provider at startup)
with the webpki root set.

## Flows

| Flow | Trigger → link | Redeemed by |
|---|---|---|
| Verify | admin create (non-invite) / admin email change of a user with a password (resets `email_verified`) / `POST me/verify-email` → `/myaccount/verify-email`, 24 h | `POST /api/authn/email/verify`: marks verified |
| Reset | `POST /api/authn/password-reset` → `/login/reset`, 30 min | `POST /api/authn/email/reset`: `directory::set_password` (all sessions + refresh / opaque tokens revoked, `must_change_password` cleared, pending reset / invite links voided), verified, notice |
| Invite | `POST users {invite: true}` / `POST users/{id}/invite` (voids the older link) / admin email change of a user without a password or passkey (re-invites at the new address) → `/login/invite`, 7 d | `POST /api/authn/email/invite`: sets the first password, verified — or `…/invite/passkey` ([passkeys](passkeys.md)): registers a passkey instead, verified; refused once the user has a password or a passkey |
| Change | `POST me/email` (re-auth; always 202, so it can't probe for accounts) → link to the NEW address `/myaccount/verify-email`, 24 h | `POST /api/authn/email/verify`: email replaced + verified (409 if taken meanwhile), every other link voided, notice to the OLD address if it was verified |

**Reset requests** answer `202` right after the IP and per-address
rate-limit buckets (both keyed without resolving the account); looking the
account up, issuing the token and queueing the mail run afterwards, detached
(`AppState::tasks`, which shutdown waits for; at most 64 in flight — past
that a request is dropped, answering the same). So status, body and response
time are the same for known, unknown, unverified and disabled addresses. A
link goes only to an enabled user whose address is verified or who holds a
pending invitation. Trade-off: the per-address limit (3 / 15 min) lets anyone
use up a victim's reset requests for a window — the same lockout trade-off
as the sign-in limits; it can't take over the account.

**Link tokens** (`mail::tokens`) are 256-bit, stored as SHA-256, consumed
atomically, only on the issuing tenant's host, for an enabled user, and only
while the user's address is still the one the token was issued for (each row
stores it, so a token issued from a stale read as an admin changes the
address never works). Anything else is the same `invalid_token`, and the
transaction rolls back (the token stays unused). Links put the token in the
URL fragment (`/login/reset#token=…`): browsers never send fragments, so no
proxy or access log sees it; the SPA reads it, strips it from the URL and
keeps it in component state only. The change-link mail goes to an unproven
address, so it names the account only by its masked current address
(`a***@example.com`), never the requester-chosen display name.

## Notices (`notify`)

Password changed (any path), MFA changed (enrol / remove / recovery codes /
passkey added or removed / admin reset), email changed, new sign-in, refresh-token reuse — each per
user × channel opt-out (`notification_prefs`, no row = on). Prefs are fully
optional by product decision: no event is locked on, so a user who switches
off `email_changed` won't be warned when their address changes. Notices go
to a verified address only; the email-changed notice goes to the OLD
address, only if it was verified, with the new address masked.

New sign-in: every new session records the browser's device cookie
(`known_devices`, SHA-256 over user id ‖ cookie, so two accounts in one
browser can't be linked); a browser unknown for the user queues the notice —
except on the user's first sign-in ever (`users.first_device_at`, which
survives the sweep of expired device rows), when every browser is new.

## Delivery

`jobs::outbox` (see [Background jobs](architecture.md#background-jobs-jobs)):
claim-then-send. A short transaction leases up to 8 due messages
(`attempts + 1`, `next_attempt_at = now + 10 min`, `FOR UPDATE SKIP LOCKED`);
8 sends × 60 s plus a 30 s skew margin must fit the 10-minute lease (a
compile-time check). Each is
then sent outside any transaction (60 s bound on the whole send), and the run
never starts a send that could end after its lease, nor one whose row another
replica has since claimed. Its outcome is recorded with its own statement,
fenced on the `(attempts, next_attempt_at)` this run claimed — a run that lost
its lease writes nothing — at the time the outcome happened: sent (body
dropped), retry after 1 m / 5 m / 30 m / 2 h / 6 h, or dead after 8 attempts
or a permanent rejection (body dropped; a CHECK forbids a body on a sent or
dead row). Shutdown stops between messages; a crash leaves the rest leased,
retried after the lease; rows a run stopped before (shutdown, or too close
to the lease's end — sends start only while the 60 s send budget plus a 30 s
clock-skew margin fits) are released: due at once, the claim's attempt
undone, so a rolling deploy doesn't hold mail for the lease. Header text with
control characters is dead at once (it can't be sent). Delivery is
at-least-once: a send in flight when its run stalls past the lease can be
repeated by the next holder, and so can a send that timed out after the
server had already accepted the message (the job can't tell, so it retries).

Pods get `terminationGracePeriodSeconds: 75` (`deploy/k8s/deploy.yml`): the
5 s preStop sleep plus a send in flight (at most 60 s) finish before the
kill.

Dev: `make dev-db` also starts Mailpit (SMTP `127.0.0.1:1025`, inbox
<http://localhost:8025>), which `.env.example`'s `SMTP_URL=smtp://localhost:1025`
points at.
