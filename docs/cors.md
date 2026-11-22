# CORS

Part of the [architecture](architecture.md); module `cors`, allowed origins of an
app set through `web_origins` ([api/applications.md](api/applications.md)).

Cross-origin SPAs (public client + PKCE on another host) need to read the
protocol endpoints from the browser. CORS — preflight and actual responses —
exists **only** on discovery, JWKS, `/oauth2/token`, `/oauth2/revoke` and
`/oauth2/userinfo`; never on the login API, the management API, introspection
(confidential clients only), `/oauth2/devicecode` or logout (the `POST` is the tenant's own SPA,
CSRF-checked by `Origin`; `GET` is a navigation).

- **Allowed origins of an app** = its explicit `web_origins` ∪, for a public
  client only, the origins of its `redirect_uris` (computed per request, never
  stored; post-logout URIs don't count). A confidential client's redirect URIs
  are server-side callbacks, so they grant nothing.
- **Origin format:** exactly what a browser sends — `https://host[:port]` or
  `http://127.0.0.1|[::1][:port]`, lowercase, no default port, no path,
  trailing slash, query, fragment, userinfo or wildcard (`cors::validate_origin`,
  enforced on `web_origins` input). Matching is an exact string compare, so a
  loopback redirect registered without a port yields the portless origin only.
- **Who may read what:** discovery, JWKS, userinfo → any origin some app of
  the tenant allows. Token / revoke → only an origin the client named in the
  request allows (Basic user name, else the form's `client_id`), whether or
  not its authentication succeeds, so an SPA can read `invalid_grant`. A
  preflight carries no body or credentials, so token / revoke preflights pass
  any origin of the tenant and the actual response is gated per client.
  Another tenant's origins mean nothing here.
- Responses always carry `Vary: Origin`; `Access-Control-Allow-Origin`
  echoes the request's `Origin` only when allowed; never
  `Access-Control-Allow-Credentials` (bearer tokens / client ids, no
  cookies). Preflights answer `204` with `Allow-Methods` (the route's),
  `Allow-Headers: authorization, content-type`, `Max-Age: 600`, or a bare
  `204` when refused. Same-origin requests (the built-in SPAs) need no CORS
  and get none. A failed origin lookup grants nothing (logged).
