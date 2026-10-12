/** Same-origin backend routes, matched by Vite's dev proxy (keys starting with `^` are regexes). */
export const API_PROXY_PATTERN = '^/api(/|$)'

// The first segment is the tenant slug, but Vite serves its own modules under `/src/…`,
// `/node_modules/…` and `/@vite|@id|@fs/…` — e.g. `/src/api/client.ts` must not be proxied.
export const TENANT_PROXY_PATTERN =
  '^/(?!(?:src|node_modules|@[^/]*)/)[^/]+/(oauth2|\\.well-known|discovery|api)(/|$)'

export const PROXY_PATTERNS = [API_PROXY_PATTERN, TENANT_PROXY_PATTERN]

export function isProxied(path: string): boolean {
  return PROXY_PATTERNS.some((p) => new RegExp(p).test(path))
}
