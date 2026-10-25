import { ApiError } from '@/api/client'
import type { UserDetail } from '@/api/types'

/** Whether "Reset MFA" has anything to remove. */
export function hasMfaFactors(mfa: UserDetail['mfa']): boolean {
  return mfa.totp || mfa.totp_pending || mfa.passkeys > 0 || mfa.telegram
}

export const RESET_MFA_MESSAGE =
  "The user's authenticator app, recovery codes and passkeys are removed and Telegram is unlinked. They can set up new ones in My Account."

export const RESET_PASSWORD_MESSAGE =
  "A new temporary password is generated and shown once. All of the user's sessions end."

/** Runs a reset-MFA call, turning the server's 409 (passkeys but no password) into advice. */
export async function resetMfaExplained(call: () => Promise<void>): Promise<void> {
  try {
    await call()
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      throw 'Set a password first (reset password) — removing their passkeys would lock them out.'
    }
    throw err
  }
}
