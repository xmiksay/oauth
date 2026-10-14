import { ApiError } from '@/api/client'
import { me } from '@/api/me'
import type { Reauth } from '@/api/types'
import { getPasskey } from '@/webauthn'

export type ReauthMethod = 'password' | 'passkey'

/** Signs a fresh `me/reauth/options` challenge with one of the user's passkeys. */
export async function passkeyReauth(): Promise<Reauth> {
  return { passkey: await getPasskey(await me.reauthOptions()) }
}

/** On `me/…` security endpoints a 403 means the re-authentication was wrong. */
export function reauthError(err: unknown, via: ReauthMethod): unknown {
  if (!(err instanceof ApiError && err.status === 403)) return err
  return via === 'password'
    ? 'Your current password is incorrect.'
    : "That passkey couldn't be verified. Try again."
}
