# Frontend (`web/`)

Part of the [architecture](architecture.md); backend contracts in
[api/authn.md](api/authn.md) and [api/management.md](api/management.md).

One Vue 3 SPA (TypeScript, Tailwind v4, Pinia, vue-router) with the `/` portal and four
areas — `/login`, `/logout`, `/myaccount`, `/admin` — built to `web/dist` and served
by the backend same-origin on every tenant host (`spa`). The tenant is the
first hostname label (`stores/tenant`; a single-label dev apex like `localhost`
redirects to `system.<host>/admin`); dev runs Vite on `*.localhost:5173`,
proxying backend paths with the `Host` kept (`PUBLIC_URL=http://localhost:5173`).

- **Portal** (`areas/portal`, route `portal` at `/`, title "Dashboard · {tenant}"): signed in
  through the **my-account** client (`meta.area: 'myaccount'`, so no extra OIDC app; the
  callback is `/myaccount/callback` and `returnTo` brings the user back to `/`). It greets the
  user (`GET me`), shows tiles for My Account and — only with a directory role
  (`auth.isAdmin`) — the Admin center, plus quick links to Security info, Devices & sessions
  and App permissions. `meta.areaInTitle: false` keeps "My Account" out of its page title.
- **App launcher** (`components/AppLauncher`, in the shared `AppHeader` of the portal, My
  Account and the admin center, on every screen size): a grid button (`aria-expanded`,
  `aria-controls`) toggling a small nav of Dashboard, My Account and Admin center (only with
  `auth.isAdmin`), the current one `aria-current="page"` with a check mark. Opening focuses the
  first entry; Escape (focus back to the button), a click outside, tabbing out or a navigation
  closes it. While open it listens for Escape on `document`, so it closes even when focus has
  left it (e.g. fallen to `body`).
  Switching areas switches the OIDC client (`auth.use`), which drops `me`; the
  target layout's `SignedInGate` reloads it with that area's token. `GET me` reports
  `directory_roles` for any client's token, so the launcher's Admin entry is right in My
  Account too.
- **Admin side nav** (`AdminLayout`): below `md` it's an overlay toggled by `AppHeader`'s
  "Toggle navigation" button. Only an Escape from inside `<nav id="side-nav">` closes it (focus
  back to the toggle through `AppHeader`'s exposed `focusMenuButton()`); Escapes from the main
  content, dialogs or the header never touch it. Crossing the `md` breakpoint (`matchMedia`
  `change`) resets it to closed, so no stale open state reappears.
- **Page layers and header height** (`style.css` `@theme`): `--z-index-backdrop` <
  `--z-index-sidenav` < `--z-index-header` give the utilities `z-backdrop` / `z-sidenav` /
  `z-header`; `--spacing-header` (the sticky `AppHeader`'s height) gives `h-header`, and the
  mobile side nav and its backdrop start at `top-header`. Only page-level layers belong there: a
  z-indexed element is the stacking context of its children, so the header's menus sit above
  the side nav because the header does, without a z-index of their own.
- **Login** (`areas/login`): `useLoginFlow` drives the login transaction of
  [api/authn.md](api/authn.md) — `GET` the step view, `POST` each step, follow
  the final `redirect` with `window.location.assign`. Same-origin `fetch` sends
  the tx-binding cookie and the `Origin` the CSRF check expects. `404` → "sign-in
  expired" (restart from the app), `409 wrong_step` → reload the view, `429` →
  form locked for `Retry-After` seconds; wrong credentials get one generic
  message. The page renders no external links (the `tx` id stays in this
  browser; the server also sends `Referrer-Policy: no-referrer`).
  When the step view's `features.password_reset` is set, the password step offers
  "Forgot password?": a detour form (`ForgotPasswordForm`, email prefilled) that
  `POST`s `/api/authn/password-reset` and always shows the same "if an account
  exists…" sentence; "Back to sign in" returns to the untouched transaction.
  The step view's `factors`
  decides which methods a step shows. With `passkey` in it and WebAuthn in the
  browser, the password step offers "Sign in with a passkey" plus autofill
  (conditional mediation, email field `autocomplete="username webauthn"`), and the
  MFA step "Use a passkey". The server keeps only the newest challenge per tx, so
  the button aborts the pending autofill `get()` (AbortController) and fetches fresh
  options; the autofill restarts (fresh options) whenever the password step is idle
  again, and fails silently. A dismissed dialog is a soft note, never an error.
  With `telegram` in the MFA step's `factors` (`TelegramFactor`; the initial mode when the
  user has no authenticator app), "Send code via Telegram" `POST`s `…/telegram/send`
  (`{ sent, expires_in }`, not a step view — the step stays) and only then shows the
  6-digit input and "Send a new code" (each send replaces the previous code); the code goes
  to `…/telegram` exactly like `…/totp`. `502 delivery_failed` → "Couldn't send the code
  via Telegram", `401 invalid_code` → "Wrong or expired code…", `503 telegram_unavailable`
  (no bot on the server) → "Telegram sign-in is unavailable…" and the MFA step stays;
  404 / 409 / 429 as above.
- **Federation (login)**: the password step shows a "Sign in with {name}" button per
  `idps` entry (below an "or" divider). A click `POST`s `…/federation/{idpId}` and follows the
  returned upstream authorize URL with a full page load (`lib/navigate.navigateTo`, never a
  router push; every button is disabled meanwhile and the card says "Redirecting to {name}…").
  With `features.federation`, leaving the email field `POST`s `…/discover` once per distinct
  address that has an `@`; an `idp` answer adds "Your organization signs in with {name}" +
  "Continue with {name}" above the password field. Discovery never blocks the form and any
  failure (a 429 included) just means no suggestion. With `idp_hint` at the password step the
  page redirects to that provider at once — at most once per page load, and **never when the URL
  has `?error=`**: the federation callback appends it after a failed upstream sign-in, so
  auto-redirecting again would loop; the hint is then a plain button (also when it isn't among
  `idps`) and the error (`federation.ts`: `upstream_failed`, `upstream_no_email`,
  `account_exists`, `account_disabled`, `not_linked`, `email_domain_not_allowed`, else
  "failed") sits above the form. A view with `notice: "link_unavailable"` (a parked link
  dropped because its provider was disabled / deleted) says so above the password form.
  `/login?error=…` without a `tx` shows "…failed or the sign-in expired". Step `link`
  (`LinkStep`) reuses the password form (email prefilled with the upstream address, passkey
  button, no providers, no discovery) to sign in to the existing account the identity gets
  linked to; MFA / consent follow as usual. There, `409 already_linked` stays on the step with
  "…already has a linked identity at this provider…", and `409 link_unavailable` reloads the
  view (back at the password step) with "The identity provider is no longer available…".
  `link.idp` is typed nullable and renders as "the identity provider".
- **Email links** (`areas/email`): `/login/reset`, `/login/invite` (choose a
  password → `POST /api/authn/email/reset|invite`) and `/myaccount/verify-email`
  (`POST /api/authn/email/verify`). They are **public** routes — no `meta.area`,
  so the guard never starts a sign-in (`/myaccount/verify-email` is a top-level
  static route that outranks the signed-in `/myaccount` subtree). `useLinkToken`
  reads `#token=` (the fragment: never sent to any server) once and immediately
  `router.replace`s it out of the URL; the
  token lives only in component state — never in a store or browser storage.
  The verify page waits for a "Confirm email address" click instead of POSTing on
  load, because mail link scanners open links and would consume the token.
  `invalid_token` → "This link is invalid, has expired or was already used." and
  the form goes away. The invite page also offers "Create a passkey instead"
  (`…/invite/passkey/options` → `create()` → `…/invite/passkey`).
- **Logout** (`areas/logout`): the RP-initiated-logout confirmation page
  (`POST /oauth2/logout`) and the `?signed_out=1` view.
- **My Account email & notifications**: the Profile page's `EmailSection` shows the
  verified badge, "Send verification link" (`POST me/verify-email`) and "Change
  email" (new address + re-authentication via `ReauthPrompt`'s slot →
  `POST me/email`; the change applies when the link sent to the new address is
  opened) — both only when `GET me` reports `features.email`. `/myaccount/notifications`
  edits `GET/PUT me/notifications` (Telegram column only while `channels.telegram`, i.e. a
  bot is configured and the user linked a chat — otherwise, with `features.telegram`, a
  pointer to Security info; email notifications go only to a verified address). In the admin center, "New user"
  can send an invitation (`invite: true`, no password) when `features.email`, and a
  user without a password gets "Resend invitation" (`POST users/{id}/invite`).
- **Passkeys** (`src/webauthn`): hand-rolled base64url and JSON ⇄ WebAuthn
  conversion (no `parseCreationOptionsFromJSON`), `createPasskey` / `getPasskey`;
  `NotAllowedError` / `AbortError` become `PasskeyCancelled`, which `ErrorAlert`
  renders as a plain note. Sensitive `me/…` calls take a `Reauth` (`{password}` or
  `{passkey}`): `ReauthPrompt` offers the password when `has_password` and a
  passkey (`me/reauth/options` → `get()`) when `mfa.passkeys > 0`. Security info
  lists passkeys (synced = `backup_state`), renames inline, removes after re-auth,
  and adds in two dialogs — re-auth → creation options, then a separate "Create
  passkey" click, since a browser may allow only one WebAuthn call per user gesture.
  Only a dismissed browser dialog keeps that second dialog open: any server answer
  closes it (the challenge is spent; retrying would orphan a credential on the
  authenticator) and the user re-authenticates for fresh options. A user with a
  passkey but no password shows as "Passkey only" in the admin center, without
  "Resend invitation".
  A passkey-only user's Password card becomes "Set a password" (passkey re-auth, no
  current-password field). The admin user detail has a Passkeys card (remove per
  passkey); Reset MFA also removes passkeys, and both explain the server's 409 for a
  user without a password.
- **Telegram** (Security info `TelegramSection`, only when `GET me` reports
  `features.telegram`): "Link Telegram" → `ReauthPrompt` → `POST me/telegram/link` →
  `window.open` of the bot deep link (`noopener,noreferrer`; also shown as a fallback
  anchor) while it polls `GET me/telegram` every 3 s until `linked` (then re-reads `me`)
  or `expires_at` passes ("The link expired"); Cancel / unmount stop polling. The link
  carries a single-use bearer code, so it lives only in the section's local state (like a
  one-time secret) and is dropped when done. "Unlink" → re-auth → `DELETE me/telegram`
  (404 = already unlinked). The admin user detail shows "Telegram linked"; Reset MFA
  unlinks it too.
- **Identity providers** (admin `areas/admin/federation`, nav "Identity providers"): list
  (`usePagedList`, no search) and detail pages over `identity-providers`; anyone with a directory
  role reads, only a Global Admin (`auth.isGlobalAdmin`) sees create / save / enable–disable /
  delete. `IdpForm` serves the create dialog and the detail page (`idpForm.ts` holds the field
  ⇄ body mapping and `changedIdpFields`, so a PATCH carries only changed fields). The client
  secret is write-only: the server only reports `has_secret` ("Secret set" / "No secret"); a typed
  secret lives in the form's local ref and is gone once saved (the form re-mounts) — an empty
  field keeps the secret, "Remove the secret" sends `client_secret: null`. The detail page shows
  `redirect_uri` with a copy button and, when `users_only_via > 0`, a lockout warning that the
  disable and delete confirmations repeat. It also shows `linked_users`; a save that repoints the
  provider (`issuer`, `client_id` or `discovery_url`) first asks for confirmation
  (`relinkWarning`) when `linked_users > 0` (the server unlinks them all) or when the issuer /
  discovery URL moves without a new secret while one is stored (the server drops it). The admin user detail lists `identities` ("Linked
  identities", unlink for `canWriteUsers`; the server's 409 for the last sign-in method shows in
  the dialog). My Account → Security has `LinkedAccountsSection` (hidden when nothing is linked or
  available): "Link {name}" → `ReauthPrompt` → `POST me/identities/{idpId}/link` → full-page
  redirect to the provider, which returns to `/myaccount/security?federation=linked` or
  `?federation_error=…` (`upstream_failed`, `already_linked`, `account_disabled`,
  `session_ended`); the section shows the outcome — "Linked {idp_name} ({email})" from the
  newest identity after reloading the list — and `router.replace`s the parameter away.
  "Unlink" → re-auth → `DELETE me/identities/{id}`.
- **Admin / My Account**: the tenant's built-in public clients `admin-portal`
  / `my-account` (code + PKCE via `oidc-client-ts`, scope
  `openid offline_access api://management-api/Directory.AccessAsUser`, authority
  = `location.origin`). One `UserManager` per area (`stores/auth`); tokens and PKCE state live
  in `sessionStorage` only. Tokens are renewed on demand with the refresh
  token, ~30 s before expiry, as ONE shared request per manager (no
  `automaticSilentRenew` timer): refresh tokens rotate and a reused one makes
  the server revoke the whole family (and audit `token.refresh_reuse`), so two
  concurrent refreshes would sign the user out (a *duplicated* tab copies
  `sessionStorage`; the loser of its first refresh just signs in again). The router
  guard (`meta.area`) starts sign-in; a management-API `401` removes the user
  and signs in again (loop-guarded), `403` renders "no permission". Sign-out
  is `end_session` with `id_token_hint` back to the area root and also drops
  the other area's tokens (same browser session).
- **API layer** (`src/api`): `client.ts` (fetch wrapper, `ApiError` with
  `code` / `description` / `retryAfter`, `errorMessage`), `management.ts`
  (bearer injection, `/api/v1` paths via `apiPath`), one typed module per resource group
  (`directory`, `applications`, `access`, `identityProviders`, `me`, `authn`), shapes in
  `types.ts` (WebAuthn wire shapes in `webauthnTypes.ts`, re-exported by it). Leaving the SPA (an app's redirect URI, an identity provider) goes through
  `lib/navigate` (`navigateTo`, `isWebUrl`: never follow a non-http(s) URL a server sends).
  Lists page with `usePagedList` (cursor stack over `next_cursor`, debounced
  search).
- UI hides actions the caller's directory roles (`GET me`) can't perform and
  shows the server's `403` for the rest. One-time secrets (passwords, client
  secrets, recovery codes) are shown only in `SecretOnceDialog` from
  component-local state — never in a store or browser storage.
- `index.html` uses an empty `data:` favicon (no 404 per page load); a future CSP
  `img-src` must allow `data:` (or serve a real `/favicon.ico`).
