// Login JSON API (`/api/authn/tx/{id}` on the tenant's host) and the sign-out POST — docs/api/authn.md.
// Same-origin fetch carries the tx-binding / session cookies and the `Origin` the CSRF check wants.
import { api } from './client'

export type LoginStep = 'password' | 'mfa' | 'change_password' | 'consent'

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
  changePassword: (tx: string, newPassword: string) =>
    api.post<StepResult>(txPath(tx, 'change-password'), { new_password: newPassword }),
  consent: (tx: string, approve: boolean, scopes: string[] = []) =>
    api.post<StepResult>(
      txPath(tx, 'consent'),
      approve ? { approve: true, scopes } : { approve: false },
    ),
  signOut: () => api.post<{ signed_out: boolean }>('/oauth2/logout', {}),
}
