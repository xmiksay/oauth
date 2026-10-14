import { useRoute, useRouter } from 'vue-router'
import { ApiError, errorMessage } from '@/api/client'

/**
 * The `#token=` of an emailed link — in the fragment so no request (hence no proxy or
 * access log) ever carries it — read once and then dropped from the URL so it doesn't
 * linger in the history (or get bookmarked). Callers keep it in component state only —
 * never in a store or browser storage.
 */
export function useLinkToken(): string | null {
  const route = useRoute()
  const router = useRouter()
  const params = new URLSearchParams(route.hash.replace(/^#/, ''))
  const raw = params.get('token')
  if (raw !== null) {
    params.delete('token')
    const rest = params.toString()
    void router.replace({ query: route.query, hash: rest ? `#${rest}` : '' })
  }
  return raw || null
}

export const INVALID_LINK = 'This link is invalid, has expired or was already used.'

/** A sentence for a failed email-link POST. */
export function linkError(err: unknown): string {
  if (err instanceof ApiError && err.code === 'invalid_token') return INVALID_LINK
  return errorMessage(err)
}
