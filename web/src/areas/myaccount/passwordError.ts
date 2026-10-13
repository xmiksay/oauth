import { ApiError } from '@/api/client'

/** On `me/…` security endpoints a 403 means the current password was wrong. */
export function passwordError(err: unknown): unknown {
  return err instanceof ApiError && err.status === 403 ? 'Your current password is incorrect.' : err
}
