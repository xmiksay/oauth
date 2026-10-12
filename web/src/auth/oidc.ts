import type { UserManagerSettings } from 'oidc-client-ts'

/** Scopes requested by the built-in SPA clients. Single source of truth — change here only. */
export const SPA_SCOPE = 'openid profile offline_access api://management/Directory.AccessAsUser'

export type SpaArea = 'admin' | 'myaccount'

const CLIENT_IDS: Record<SpaArea, string> = {
  admin: 'admin-portal',
  myaccount: 'my-account',
}

export function buildOidcSettings(
  tenant: string,
  area: SpaArea,
  origin: string = window.location.origin,
): UserManagerSettings {
  const base = `${origin}/${encodeURIComponent(tenant)}`
  return {
    authority: base,
    client_id: CLIENT_IDS[area],
    redirect_uri: `${base}/${area}/callback`,
    post_logout_redirect_uri: `${base}/${area}`,
    response_type: 'code',
    scope: SPA_SCOPE,
  }
}
