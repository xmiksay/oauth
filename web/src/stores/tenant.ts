import { defineStore } from 'pinia'
import { ref } from 'vue'

/**
 * The tenant of a `{slug}.{base host}` hostname: its first label. `null` only for a
 * single-label host such as the dev apex `localhost` (a production apex like
 * `id.example.com` never serves the SPA: the server redirects or 404s there).
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

/** Admin center of the system tenant, as seen from a single-label dev apex. */
export function systemAdminUrl(loc: Pick<Location, 'protocol' | 'host'> = window.location): string {
  return `${loc.protocol}//system.${loc.host}/admin`
}

export const useTenantStore = defineStore('tenant', () => {
  // Fixed for the page's lifetime: another tenant is another host, hence a full navigation.
  const slug = ref<string | null>(tenantFromHostname(location.hostname))
  return { slug }
})
