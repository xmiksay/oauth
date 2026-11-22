import { defineStore } from 'pinia'
import { ref } from 'vue'

/**
 * The tenant the server wrote into `index.html` (`<meta name="oauth-tenant">`, see `spa.rs`).
 * Absent only under the Vite dev server, which serves its own `index.html`.
 */
export function tenantFromMeta(doc: Pick<Document, 'querySelector'> = document): string | null {
  return doc.querySelector('meta[name="oauth-tenant"]')?.getAttribute('content') || null
}

/**
 * The tenant of a `{slug}.{base host}` hostname: its first label. `null` only for a
 * single-label host such as the dev apex `localhost`. Wrong on a production apex serving
 * `APEX_TENANT` (`id.example.com` is not tenant `id`), hence {@link currentTenant}.
 */
export function tenantFromHostname(hostname: string): string | null {
  const [first, ...rest] = hostname.toLowerCase().split('.')
  return first && rest.length > 0 && rest.every(Boolean) ? first : null
}

/** Origin of tenant `slug`: the current host with its first label swapped. */
export function tenantOrigin(
  slug: string,
  loc: Pick<Location, 'protocol' | 'host'> = window.location,
): string {
  const base = loc.host.slice(loc.host.indexOf('.') + 1)
  return `${loc.protocol}//${slug}.${base}`
}

/**
 * Admin center of the system tenant, as seen from a single-label dev apex. `slug` defaults to
 * `SYSTEM_TENANT_SLUG` of the dev `.env` under the Vite dev server, else `system` (see
 * `tenant-defines.ts`).
 */
export function systemAdminUrl(
  loc: Pick<Location, 'protocol' | 'host'> = window.location,
  slug: string = __SYSTEM_TENANT_SLUG__,
): string {
  return `${loc.protocol}//${slug}.${loc.host}/admin`
}

/**
 * The page's tenant: the server's `<meta>` first; under the Vite dev server the host's first
 * label, or on the single-label dev apex the dev `.env`'s `APEX_TENANT` (`null` without one, and
 * always in builds and tests: the dev apex then redirects to the system admin center).
 */
export function currentTenant(
  doc: Pick<Document, 'querySelector'> = document,
  hostname: string = location.hostname,
  apexTenant: string = __APEX_TENANT__,
): string | null {
  return tenantFromMeta(doc) ?? tenantFromHostname(hostname) ?? (apexTenant || null)
}

export const useTenantStore = defineStore('tenant', () => {
  // Fixed for the page's lifetime: another tenant is another host, hence a full navigation.
  const slug = ref<string | null>(currentTenant())
  return { slug }
})
