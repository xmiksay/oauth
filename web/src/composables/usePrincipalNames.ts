import { reactive } from 'vue'
import { users, groups } from '@/api/directory'
import { applications } from '@/api/applications'
import type { PrincipalType } from '@/api/types'

/**
 * Display names for ids returned by assignment lists (which carry ids only). Fetched lazily,
 * once per id; until then (or if the lookup fails) the id itself is shown.
 */
export function usePrincipalNames() {
  const names = reactive(new Map<string, string>())
  const pending = new Set<string>()

  async function lookup(kind: PrincipalType, id: string): Promise<string> {
    switch (kind) {
      case 'user': {
        const u = await users.get(id)
        return u.display_name ? `${u.display_name} (${u.email})` : u.email
      }
      case 'group':
        return (await groups.get(id)).display_name
      case 'application':
        return (await applications.get(id)).display_name
    }
  }

  /** The display name, or `fallback` (default: the id) until it is known or if lookup fails. */
  function name(kind: PrincipalType, id: string, fallback = id): string {
    const known = names.get(id)
    if (known !== undefined) return known || fallback
    if (!pending.has(id)) {
      pending.add(id)
      lookup(kind, id)
        .then((n) => names.set(id, n))
        .catch(() => names.set(id, ''))
    }
    return fallback
  }

  return { name }
}
