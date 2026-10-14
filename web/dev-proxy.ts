/**
 * Backend routes the Vite dev server proxies (a key starting with `^` is a regex). The tenant is
 * the host (`acme.localhost:5173`), so these are root paths on every host; Vite's own modules
 * (`/src`, `/node_modules`, `/@vite`…) never start with one of them.
 */
export const BACKEND_PROXY_PATTERN = '^/(api|oauth2|\\.well-known|discovery)(/|$)'

export function isProxied(path: string): boolean {
  return new RegExp(BACKEND_PROXY_PATTERN).test(path)
}
