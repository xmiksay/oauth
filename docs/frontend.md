# Frontend (`web/`)

Part of the [architecture](architecture.md); backend contracts in
[api/authn.md](api/authn.md) and [api/management.md](api/management.md).

One Vue 3 SPA (TypeScript, Tailwind v4, Pinia, vue-router) with four areas —
`/login`, `/logout`, `/myaccount`, `/admin` — built to `web/dist` and served
by the backend same-origin on every tenant host (`spa`). The tenant is the
first hostname label (`stores/tenant`; a single-label dev apex like `localhost`
redirects to `system.<host>/admin`); dev runs Vite on `*.localhost:5173`,
proxying backend paths with the `Host` kept (`PUBLIC_URL=http://localhost:5173`).

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
  the form goes away.
- **Logout** (`areas/logout`): the RP-initiated-logout confirmation page
  (`POST /oauth2/logout`) and the `?signed_out=1` view.
- **My Account email & notifications**: the Profile page's `EmailSection` shows the
  verified badge, "Send verification link" (`POST me/verify-email`) and "Change
  email" (new address + current password via `PasswordPrompt`'s slot →
  `POST me/email`; the change applies when the link sent to the new address is
  opened) — both only when `GET me` reports `features.email`. `/myaccount/notifications`
  edits `GET/PUT me/notifications` (Telegram column only when that channel exists;
  notifications go only to a verified address). In the admin center, "New user"
  can send an invitation (`invite: true`, no password) when `features.email`, and a
  user without a password gets "Resend invitation" (`POST users/{id}/invite`).
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
  (`directory`, `applications`, `access`, `me`, `authn`), shapes in `types.ts`.
  Lists page with `usePagedList` (cursor stack over `next_cursor`, debounced
  search).
- UI hides actions the caller's directory roles (`GET me`) can't perform and
  shows the server's `403` for the rest. One-time secrets (passwords, client
  secrets, recovery codes) are shown only in `SecretOnceDialog` from
  component-local state — never in a store or browser storage.
- `index.html` uses an empty `data:` favicon (no 404 per page load); a future CSP
  `img-src` must allow `data:` (or serve a real `/favicon.ico`).
