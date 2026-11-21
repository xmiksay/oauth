// Login JSON API (`/api/authn/tx/{id}` on the tenant's host) and the sign-out POST — docs/api/authn.md.
// Same-origin fetch carries the tx-binding / session cookies and the `Origin` the CSRF check wants.
import { api } from './client'
import type {
  IdpRef,
  PasskeyAssertion,
  PasskeyCreationOptions,
  PasskeyRegistration,
  PasskeyRequestOptions,
  TotpEnrollment,
} from './types'

/**
 * `link`: an upstream identity waits to be linked by signing in to an existing account.
 * `mfa_enroll`: MFA is required and the user has no second factor yet — they set one up.
 */
export type LoginStep = 'password' | 'link' | 'mfa' | 'mfa_enroll' | 'change_password' | 'consent'

export type LoginFactor = 'password' | 'passkey' | 'totp' | 'recovery' | 'telegram'

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
  /** `federation`: the tenant has an enabled identity provider (email-domain discovery). */
  features: { password_reset: boolean; federation: boolean }
  /** Methods the current step accepts. */
  factors: LoginFactor[]
  /** Identity providers offered as buttons at the password step. */
  idps: IdpRef[]
  /** The authorize request named this provider (`idp=` / a mapped `domain_hint=`). */
  idp_hint: IdpRef | null
  /** At step `link`: the upstream identity waiting to be linked. */
  link: { idp: IdpRef | null; email: string | null; name: string | null } | null
  /** At step `password`: a parked link was dropped (its provider was disabled or deleted). */
  notice: 'link_unavailable' | null
  /**
   * The sign-in approves a device (RFC 8628 device code): it always ends with a confirmation,
   * whose `consent.scopes` then lists everything the device gets.
   */
  device: boolean
  /**
   * The OpenID Connect scopes of the request (`openid`, `profile`, `email`, `offline_access`);
   * a device confirmation names them, `offline_access` above all (a long-lived refresh token).
   */
  oidc_scopes: string[]
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

/** Confirming a TOTP enrolment: the next step plus the new recovery codes (shown once). */
export type EnrolledResult = StepResult & { recovery_codes: string[] }

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
  /** Sends a fresh code (replacing the previous one) to the user's linked Telegram chat. */
  sendTelegramCode: (tx: string) =>
    api.post<{ sent: boolean; expires_in: number }>(txPath(tx, 'telegram/send'), {}),
  submitTelegram: (tx: string, code: string) =>
    api.post<StepResult>(txPath(tx, 'telegram'), { code }),
  recovery: (tx: string, code: string) => api.post<StepResult>(txPath(tx, 'recovery'), { code }),
  /** The server keeps only the newest challenge per transaction. */
  passkeyOptions: (tx: string) =>
    api.post<PasskeyRequestOptions>(txPath(tx, 'passkey/options'), {}),
  passkey: (tx: string, assertion: PasskeyAssertion) =>
    api.post<StepResult>(txPath(tx, 'passkey'), assertion),
  /** The upstream authorize URL to navigate to (a full page load, it's another origin). */
  federation: (tx: string, idpId: string) =>
    api.post<Redirect>(txPath(tx, `federation/${encodeURIComponent(idpId)}`), {}),
  /** `idp` when the email's domain belongs to a provider. */
  discover: (tx: string, email: string) =>
    api.post<{ idp?: IdpRef }>(txPath(tx, 'discover'), { email }),
  /** `mfa_enroll`: a new pending TOTP secret (replaces an unconfirmed one). */
  enrollTotp: (tx: string) => api.post<TotpEnrollment>(txPath(tx, 'enroll/totp'), {}),
  confirmEnrollTotp: (tx: string, code: string) =>
    api.post<EnrolledResult>(txPath(tx, 'enroll/totp/confirm'), { code }),
  enrollPasskeyOptions: (tx: string) =>
    api.post<PasskeyCreationOptions>(txPath(tx, 'enroll/passkey/options'), {}),
  enrollPasskey: (tx: string, credential: PasskeyRegistration) =>
    api.post<StepResult>(txPath(tx, 'enroll/passkey'), { credential }),
  changePassword: (tx: string, newPassword: string) =>
    api.post<StepResult>(txPath(tx, 'change-password'), { new_password: newPassword }),
  consent: (tx: string, approve: boolean, scopes: string[] = []) =>
    api.post<StepResult>(
      txPath(tx, 'consent'),
      approve ? { approve: true, scopes } : { approve: false },
    ),
  signOut: () => api.post<{ signed_out: boolean }>('/oauth2/logout', {}),
  /** A device's user code (`/device`): the login transaction to continue with. */
  deviceCode: (userCode: string) => api.post<Redirect>('/api/authn/device', { user_code: userCode }),
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
