// Login JSON API (`/{t}/api/authn/tx/{id}`) and the sign-out POST — docs/api/authn.md.
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

function txPath(tenant: string, tx: string, action = ''): string {
  const base = `/${encodeURIComponent(tenant)}/api/authn/tx/${encodeURIComponent(tx)}`
  return action ? `${base}/${action}` : base
}

export const authn = {
  get: (tenant: string, tx: string) => api.get<TxView>(txPath(tenant, tx)),
  password: (tenant: string, tx: string, email: string, password: string) =>
    api.post<StepResult>(txPath(tenant, tx, 'password'), { email, password }),
  totp: (tenant: string, tx: string, code: string) =>
    api.post<StepResult>(txPath(tenant, tx, 'totp'), { code }),
  recovery: (tenant: string, tx: string, code: string) =>
    api.post<StepResult>(txPath(tenant, tx, 'recovery'), { code }),
  changePassword: (tenant: string, tx: string, newPassword: string) =>
    api.post<StepResult>(txPath(tenant, tx, 'change-password'), { new_password: newPassword }),
  consent: (tenant: string, tx: string, approve: boolean, scopes: string[] = []) =>
    api.post<StepResult>(
      txPath(tenant, tx, 'consent'),
      approve ? { approve: true, scopes } : { approve: false },
    ),
  signOut: (tenant: string) =>
    api.post<{ signed_out: boolean }>(`/${encodeURIComponent(tenant)}/oauth2/logout`, {}),
}
