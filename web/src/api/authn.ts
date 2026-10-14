// Login JSON API (`/api/authn/tx/{id}` on the tenant's host) and the sign-out POST — docs/api/authn.md.
// Same-origin fetch carries the tx-binding / session cookies and the `Origin` the CSRF check wants.
import { api } from './client'
import type {
  PasskeyAssertion,
  PasskeyCreationOptions,
  PasskeyRegistration,
  PasskeyRequestOptions,
} from './types'

export type LoginStep = 'password' | 'mfa' | 'change_password' | 'consent'

export type LoginFactor = 'password' | 'passkey' | 'totp' | 'recovery'

export interface ConsentScope {
  value: string
  description: string
}

export interface TxView {
  tx: string
  step: LoginStep
  tenant: { slug: string; display_name: string }
  client: { client_id: string; display_name: string }
  user: { email: string; display_name: string } | null
  consent: {
    resource: { display_name: string; audience: string }
    scopes: ConsentScope[]
  } | null
  features: { password_reset: boolean }
  /** Methods the current step accepts. */
  factors: LoginFactor[]
}

export interface EmailVerified {
  /** `change`: the link confirmed a new sign-in address. */
  purpose: 'verify' | 'change'
  email: string
}

export interface Redirect {
  redirect: string
}

export type StepResult = TxView | Redirect

export function isRedirect(r: StepResult): r is Redirect {
  return typeof (r as Redirect).redirect === 'string'
}

function txPath(tx: string, action = ''): string {
  const base = `/api/authn/tx/${encodeURIComponent(tx)}`
  return action ? `${base}/${action}` : base
}

export const authn = {
  get: (tx: string) => api.get<TxView>(txPath(tx)),
  password: (tx: string, email: string, password: string) =>
    api.post<StepResult>(txPath(tx, 'password'), { email, password }),
  totp: (tx: string, code: string) => api.post<StepResult>(txPath(tx, 'totp'), { code }),
  recovery: (tx: string, code: string) => api.post<StepResult>(txPath(tx, 'recovery'), { code }),
  /** The server keeps only the newest challenge per transaction. */
  passkeyOptions: (tx: string) =>
    api.post<PasskeyRequestOptions>(txPath(tx, 'passkey/options'), {}),
  passkey: (tx: string, assertion: PasskeyAssertion) =>
    api.post<StepResult>(txPath(tx, 'passkey'), assertion),
  changePassword: (tx: string, newPassword: string) =>
    api.post<StepResult>(txPath(tx, 'change-password'), { new_password: newPassword }),
  consent: (tx: string, approve: boolean, scopes: string[] = []) =>
    api.post<StepResult>(
      txPath(tx, 'consent'),
      approve ? { approve: true, scopes } : { approve: false },
    ),
  signOut: () => api.post<{ signed_out: boolean }>('/oauth2/logout', {}),
  // Email-link endpoints: not tied to a transaction; the link's token authorizes them.
  requestPasswordReset: (email: string) =>
    api.post<{ accepted: boolean }>('/api/authn/password-reset', { email }),
  verifyEmail: (token: string) => api.post<EmailVerified>('/api/authn/email/verify', { token }),
  resetPassword: (token: string, newPassword: string) =>
    api.post<void>('/api/authn/email/reset', { token, new_password: newPassword }),
  acceptInvite: (token: string, newPassword: string) =>
    api.post<void>('/api/authn/email/invite', { token, new_password: newPassword }),
  invitePasskeyOptions: (token: string) =>
    api.post<PasskeyCreationOptions>('/api/authn/email/invite/passkey/options', { token }),
  acceptInviteWithPasskey: (token: string, credential: PasskeyRegistration) =>
    api.post<void>('/api/authn/email/invite/passkey', { token, credential }),
}
