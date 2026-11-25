# HTTP surface

Tenant `{t}` lives only at `{t}.{PUBLIC_URL host}[:port]`; its issuer is that origin. The
optional `APEX_TENANT` lives only on the apex instead (`PUBLIC_URL` is its origin and issuer;
its subdomain → 404; [deploy.md](deploy.md#apex-tenant)). `Config::tenant_origin` /
`issuer` / `tenant_rp_id` are the only places that map a slug to its origin, so issuer,
redirect URIs, CSRF / CORS origin, RP ID, links and federation callback all follow it.
`tenancy::resolve_host` gates every route but the probes. The request authority is the
absolute-form target / HTTP/2 `:authority` if present, else `Host` (RFC 9112 §3.2.2); more
than one `Host` header → 400. It must match exactly: ASCII case-insensitive, the scheme's
default port (`:443` for https, `:80` for http) spelled out counts as none; another port, trailing dot, nested label or
IP literal → 404. `X-Forwarded-Host` / `Forwarded` are never trusted. Unknown or disabled
tenants are 404 everywhere, and so are enabled tenants whose slug today's rules reject or
that hold a slug the system tenant was renamed away from (`retired_tenant_slugs`; startup
refuses to run with any — rename or disable them). Without `APEX_TENANT` the apex serves
only `GET /` → 302 `{scheme}://{SYSTEM_TENANT_SLUG}.{host}/admin` and the Telegram webhook (404 on tenant
hosts); with it, the webhook and that tenant's routes (startup refuses an `APEX_TENANT` that is
the system tenant, missing or disabled). Other paths below are per tenant host.

Trust model: issuer, redirect URLs and the CSRF origin all derive from `PUBLIC_URL` plus
the tenant's slug in the DB, never from request text, so a client choosing its `Host`
only reaches a tenant it could visit anyway. Hence no shared cache or CDN in front may
key responses on the path without the host, and the ingress must forward `Host`
unchanged (ingress-nginx: leave `use-forwarded-headers` off unless another trusted
proxy sits in front; the server ignores the forwarded host either way).

| Route | Listener | Module |
|---|---|---|
| `GET /healthz` — process alive, no DB dependency (any host) | app | `health` |
| `GET /readyz` — migrations done + DB ping, else 503 (any host) | app | `health` |
| `GET /` on the apex → 302 to the system admin portal (without `APEX_TENANT`) | app | `tenancy` |
| `POST /telegram/webhook` on the apex — bot updates, secret-token authenticated ([telegram.md](telegram.md)) | app | `telegram::webhook` |
| `GET /.well-known/openid-configuration` (CORS: [cors.md](cors.md) for this and JWKS / token / userinfo / revoke, incl. `OPTIONS` preflights) | app | `oidc::discovery`, `cors` |
| `GET /discovery/keys` — JWKS (next + active + unexpired retired), `max-age=300` | app | `oidc::discovery` |
| `GET /oauth2/authorize` | app | `oidc::authorize` |
| `POST /oauth2/token`, `POST /oauth2/devicecode` (RFC 8628 device authorization) | app | `oidc::token`, `oidc::refresh_grant`, `oidc::device_grant`, `oidc::device_authorization` |
| `GET\|POST /oauth2/userinfo` | app | `oidc::userinfo` |
| `POST /oauth2/introspect` (RFC 7662) | app | `oidc::introspect` |
| `POST /oauth2/revoke` (RFC 7009) | app | `oidc::revoke` |
| `GET /oauth2/logout` (RP-initiated), `POST` (confirmation page, CSRF-checked) | app | `oidc::logout` |
| `GET /api/authn/tx/{id}`, `POST …/{password,totp,recovery,passkey/options,passkey,telegram/send,telegram,enroll/totp,enroll/totp/confirm,enroll/passkey/options,enroll/passkey,enroll/continue,change-password,consent,federation/{idp},discover}` — login JSON API, contract in [api/authn.md](api/authn.md) | app | `authn` |
| `GET /federation/callback` — return from an upstream identity provider ([federation.md](federation.md)) | app | `authn::federation` |
| `POST /api/authn/password-reset`, `POST /api/authn/email/{verify,reset,invite,invite/passkey/options,invite/passkey}` — email links (the token is the credential), same contract | app | `authn::{reset,email}` |
| `POST /api/authn/device` — a device's user code entered on `/device` → login transaction, same contract | app | `authn::device_code` |
| `/api/v1/{settings,users,groups,directory-roles,applications,identity-providers,role-assignments,consents,audit-events}[/…]`, `/api/v1/me[/…]`, and on the system host only `/api/v1/tenants[/{slug}[/users[/…]]]` (system Global Admins) — management REST API, bearer tokens for the host tenant's `management-api`; contract in [api/management.md](api/management.md) (+ [applications](api/applications.md), [identity providers](api/identity_providers.md)) | app | `api` |
| `/` (the portal; apex `/` redirects without `APEX_TENANT`, above; with it the apex serves that tenant's SPA), `/index.html` and `/{login,logout,device,myaccount,admin}[/…]` → `index.html` with `<meta name="oauth-build" content="{version}+{commit}">` and `<meta name="oauth-tenant" content="{slug}">` (`Cache-Control: no-cache`) (incl. the public link pages `/login/reset`, `/login/invite`, `/myaccount/verify-email`) | app | `spa` |
| any other path → static file from `WEB_DIST_DIR`, else 404 | app | `spa` |
| `GET /metrics` — Prometheus text format | metrics | `metrics` |

A missing SPA build only logs a warning; SPA routes then return 404.
