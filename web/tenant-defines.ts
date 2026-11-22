/** Fixed values for builds and vitest: served builds take the tenant from the server's `<meta>`. */
export const DEFAULT_TENANT_DEFINES: Readonly<Record<string, string>> = {
  __SYSTEM_TENANT_SLUG__: JSON.stringify('system'),
  __APEX_TENANT__: JSON.stringify(''),
}

const SLUG = /^[a-z0-9][a-z0-9-]{1,62}$/

function slug(read: (key: string) => string | undefined, key: string, fallback: string): string {
  const value = (read(key) ?? '').trim() || fallback
  if (value && !SLUG.test(value)) {
    throw new Error(`${key} \`${value}\` is not a valid tenant slug`)
  }
  return value
}

/**
 * Only the dev apex (`localhost:5173`, served by Vite, so without the server's tenant `<meta>`)
 * needs these: the system tenant's slug, to send the browser to its admin center as the server's
 * apex does, or the `APEX_TENANT` it serves instead. So only the dev server (`serve` outside
 * vitest) reads them, through `read` (the backend's `.env`), trimmed like the server does; builds
 * and tests get {@link DEFAULT_TENANT_DEFINES}, so a developer's `.env` can neither change test
 * results nor break `make web-build`. A malformed slug, or an `APEX_TENANT` naming the system
 * tenant, fails the dev server loudly; whether the tenant exists, is enabled or reserved only the
 * server knows.
 */
export function tenantDefines(
  devServer: boolean,
  read: (key: string) => string | undefined,
): Record<string, string> {
  if (!devServer) return { ...DEFAULT_TENANT_DEFINES }
  const system = slug(read, 'SYSTEM_TENANT_SLUG', 'system')
  const apex = slug(read, 'APEX_TENANT', '')
  if (apex === system) {
    throw new Error(`APEX_TENANT \`${apex}\` is the system tenant, which the apex cannot serve`)
  }
  return { __SYSTEM_TENANT_SLUG__: JSON.stringify(system), __APEX_TENANT__: JSON.stringify(apex) }
}
