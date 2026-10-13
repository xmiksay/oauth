import { ApiError, request, type RequestOptions } from './client'
import type { PageQuery, Paged } from './types'
import { useAuthStore } from '@/stores/auth'

/** Management API request with the signed-in user's bearer token; a 401 triggers re-auth. */
export async function authed<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const auth = useAuthStore()
  const token = await auth.accessToken()
  try {
    return await request<T>(path, {
      ...opts,
      headers: { ...opts.headers, Authorization: `Bearer ${token}` },
    })
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) await auth.reauthenticate()
    throw err
  }
}

/** `/api/v1/tenants/{t}/{rel}` for the tenant the user signed in to. */
export function tenantPath(rel: string): string {
  const t = useAuthStore().tenant ?? ''
  return `/api/v1/tenants/${encodeURIComponent(t)}/${rel}`
}

const seg = encodeURIComponent

/** Tenant-relative verbs; `rel` is e.g. `users/${id}`. */
export const t = {
  get: <T>(rel: string) => authed<T>(tenantPath(rel)),
  post: <T>(rel: string, body: unknown = {}) => authed<T>(tenantPath(rel), { method: 'POST', body }),
  patch: <T>(rel: string, body: unknown) => authed<T>(tenantPath(rel), { method: 'PATCH', body }),
  del: (rel: string, body?: unknown) =>
    authed<void>(tenantPath(rel), { method: 'DELETE', body }),
}

/** Every item of a paged list (follows `next_cursor` with the maximum page size). */
export async function allPages<T>(fetchPage: (q: PageQuery) => Promise<Paged<T>>): Promise<T[]> {
  const out: T[] = []
  let cursor: string | null = null
  do {
    const page: Paged<T> = await fetchPage({ limit: 200, cursor })
    out.push(...page.items)
    cursor = page.next_cursor
  } while (cursor)
  return out
}

/** Path segment builder that escapes every dynamic part. */
export function p(strings: TemplateStringsArray, ...parts: string[]): string {
  return strings.reduce((acc, s, i) => acc + s + (i < parts.length ? seg(parts[i] ?? '') : ''), '')
}
