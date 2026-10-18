# Telegram

Part of the [architecture](architecture.md); endpoint contracts in
[api/authn.md](api/authn.md) (sign-in codes), [api/me.md](api/me.md)
(linking) and [api/management.md](api/management.md) (admin). Code in
`crates/server/src/telegram/`.

A user links one Telegram chat with the IdP's bot. The chat then gets
**sign-in codes** — Telegram becomes an MFA method — and **security notices**
(the same events as email, toggled per event in My Account → Notifications).
Optional: without the bot settings every Telegram feature is hidden
(`features.telegram` false, webhook and `me/telegram` 404, login code calls
`503 telegram_unavailable`, notices email only) — but see "fails closed" below.

## Setup

1. Create a bot with [@BotFather](https://t.me/BotFather) (`/newbot`); note the
   token and the username.
2. Configure (all three or none; startup refuses a partial set):

   | Variable | Where | |
   |---|---|---|
   | `TELEGRAM_BOT_TOKEN` | Secret | `<id>:<key>` from BotFather; never logged (`Debug` redacts it) |
   | `TELEGRAM_BOT_USERNAME` | ConfigMap | without `@`; deep links are `https://t.me/<username>?start=<code>` |
   | `TELEGRAM_WEBHOOK_SECRET` | Secret | 1–256 of `A-Za-z0-9_-` (the Bot API's rule), e.g. `openssl rand -hex 32` |
   | `TELEGRAM_API_URL` | ConfigMap | default `https://api.telegram.org`; `http://` only to a loopback host (tests, a local Bot API server) |

3. Register the webhook once, and again whenever the secret or `PUBLIC_URL`
   changes: `make telegram-webhook` locally, or
   `kubectl exec deploy/oauth -- oauth telegram set-webhook`. It calls
   `setWebhook` with `url = {PUBLIC_URL}/telegram/webhook` (the apex origin,
   which belongs to no tenant), `secret_token` and
   `allowed_updates = ["message"]`. Telegram only calls https URLs on ports
   443, 80, 88 or 8443; local development needs a tunnel to the apex.

One bot serves every tenant: the link code decides which tenant's user a
chat is linked to, and the bot's replies name that tenant.

**Removing the bot fails closed.** Whether a user has Telegram as a second
factor comes from their link alone, not from the bot settings: with
`TELEGRAM_*` unset (or a client that can't be built — then the server
treats Telegram as unset everywhere) a linked user still reaches the MFA
step. `telegram` is then offered only if the user has no other factor, and
sending or submitting a code answers `503 telegram_unavailable` — they sign
in with another factor, or an admin runs **Reset MFA**. Startup logs a warning with the number of linked users when
Telegram is unset.

## Webhook (`POST /telegram/webhook`, apex host only)

- Authenticated by `X-Telegram-Bot-Api-Secret-Token`, compared in constant
  time with `TELEGRAM_WEBHOOK_SECRET`; missing or wrong → `401`, nothing
  processed. On a tenant host the path is 404. Bodies over 64 KiB → `413`.
- Only `message` updates with text, from a human (`from.is_bot` false), in a
  chat of type `private` are acted on — in a group anyone could post another
  member's code or `/stop`. Everything else authenticated is ignored with
  `200` (empty body), so Telegram doesn't redeliver it.
- The reply is the webhook **response** (`{"method": "sendMessage", …}`,
  which Telegram executes), so the webhook never waits on the Bot API. A
  database error answers `500` with nothing committed; Telegram retries.

| Message | Effect |
|---|---|
| `/start <code>` | Consumes the link code (one `DELETE … RETURNING` on its SHA-256: single use, expired codes never match) and links this chat to its user, replacing the user's earlier chat; audit `user.mfa.telegram_link` (`via: bot`), "MFA changed" notice. Reply names the tenant and the masked address. A chat may be linked to several users (one person in several tenants) |
| `/start` with a missing / unknown / expired / used code, or one of a since-disabled user or tenant | Generic "invalid or has expired" reply (the code is spent) |
| `/stop` | Unlinks every user linked to this chat (each audited `user.mfa.telegram_unlink`, `via: bot`, and sent the "MFA changed" notice — by email, as the chat is gone) |
| anything else | Short help text |

## Linking (My Account)

`POST me/telegram/link` (re-authentication: password or passkey) returns
`{ url: "https://t.me/<bot>?start=<code>", expires_at }`. The code is 256
random bits (base64url, 43 characters — Telegram passes up to 64), stored as
SHA-256, valid 10 minutes, one live code per user (a new request voids the
old one). The SPA opens the link and polls `GET me/telegram` until it reports
`linked`. `DELETE me/telegram` (re-authentication) unlinks; so does an admin
**Reset MFA** and the user's `/stop`. Unlinking — and linking a new chat —
also drops the user's pending link and sign-in codes (a code sent to the old
chat is dead).

## Sign-in codes

A linked user (with the bot configured) reaches the MFA step after the
password like with TOTP or a passkey; `factors` contains `telegram`.

- `POST /api/authn/tx/{tx}/telegram/send` generates 6 digits
  (`secret::random_string`: AWS-LC RNG, rejection sampling, no modulo bias),
  stores SHA-256 over `tx id ‖ code` as the transaction's live code (a new
  send replaces the code and resets its guesses), then sends it inline
  (10 s bound) — a failure is `502 delivery_failed` and the user retries.
  Sends are limited to **3 per 15 minutes per user**, across transactions.
- `POST /api/authn/tx/{tx}/telegram {code}`: every call first spends one of
  the code's **5 guesses** (an `UPDATE … WHERE attempts < 5 AND expires_at >
  now()`, so concurrent guesses can't exceed it), then compares the hash in
  constant time; a match deletes the code (fenced on its hash: single use)
  and the sign-in continues like TOTP with `amr = ["pwd","otp","mfa"]`.
  Codes live **5 minutes**. Wrong / expired / used / dead are the same
  `401 invalid_code`, audited as `sign_in` failures with `factor: telegram`;
  the per-IP and per-account sign-in limits apply too.
- Codes belong to their login transaction (FK, cascade) and are swept with
  the link codes once expired.

Trade-off: Telegram is a possession factor only as strong as the user's
Telegram account (SIM-swap recovery of Telegram accounts, cloud chats). It
ranks with SMS-like OTP — weaker than TOTP or passkeys, which a user can add
alongside. Accepted as well:

- `/stop` removes the factor without re-authenticating at the IdP: whoever
  controls the Telegram session can do it (they then also lose the codes;
  the user is told by email).
- Someone who knows the password can use up the user's 3 sends / 15 min and
  so block Telegram sign-in for a window (the same trade-off as the account
  sign-in limit); another factor or an admin Reset MFA recovers.

## Notices

`notify::event` queues an outbox row with `channel = telegram` and
`recipient` = the user id when the bot is configured, the user is linked and
the event's `telegram` preference is on (default). The outbox job delivers
telegram rows separately from email ([email.md](email.md#delivery): same
lease, fencing, backoff and dead rules) by `sendMessage` to the chat linked
**at send time** — no link any more → dead at once, never retried; Bot API
429 / 5xx / network errors retry, other refusals (e.g. the user blocked the
bot) are permanent. The text is the email notice (subject + body). Bodies
are sealed at rest like email; chat ids and texts are never logged.

## Data

| Table | Notes |
|---|---|
| `telegram_links` | (tenant, user) unique, `chat_id` (indexed, several users per chat), `username` (the Telegram @name at link time), `linked_at` |
| `telegram_link_codes` | `code_hash` unique, user, `expires_at` 10 min; deleted when used |
| `telegram_otps` | (tenant, tx) unique → `login_transactions`, user, `code_hash`, `attempts` ≤ 5, `sent_at`, `expires_at` 5 min |

The HTTP client is reqwest on rustls with an explicit AWS-LC provider and
the webpki roots (no OpenSSL, no native TLS, no system proxy lookup, no
redirects); reqwest errors are never logged as text, because they embed the
URL and with it the bot token.
