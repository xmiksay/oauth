import { UserManager, WebStorageStateStore, type UserManagerSettings } from 'oidc-client-ts'

/**
 * Scopes requested by the built-in SPA clients. Single source of truth — change here only.
 * The resource prefix is the management API's `identifier_uri` (`api://management-api`,
 * provisioned in `directory/builtin_apps.rs`); `offline_access` gets a refresh token for
 * silent renew.
 */
export const SPA_SCOPE = 'openid offline_access api://management-api/Directory.AccessAsUser'

export type SpaArea = 'admin' | 'myaccount'

const CLIENT_IDS: Record<SpaArea, string> = {
  admin: 'admin-portal',
  myaccount: 'my-account',
}

export function areaUrl(area: SpaArea, origin = window.location.origin): string {
  return `${origin}/${area}`
}

/** The page's host is the tenant, so its origin is the OIDC authority (= issuer). */
export function buildOidcSettings(
  area: SpaArea,
  origin: string = window.location.origin,
): UserManagerSettings {
  const base = areaUrl(area, origin)
  return {
    authority: origin,
    client_id: CLIENT_IDS[area],
    redirect_uri: `${base}/callback`,
    post_logout_redirect_uri: base,
    response_type: 'code',
    scope: SPA_SCOPE,
  }
}

export function createUserManager(area: SpaArea): UserManager {
  // Tokens and PKCE state stay in sessionStorage (per tab, gone with it) — never localStorage.
  const store = new WebStorageStateStore({ store: window.sessionStorage })
  return new UserManager({
    ...buildOidcSettings(area),
    userStore: store,
    stateStore: store,
    // Renewal is on demand (stores/auth `accessToken`, single-flight): a background timer per
    // manager could redeem the same rotating refresh token twice and trip reuse detection.
    automaticSilentRenew: false,
    monitorSession: false,
    loadUserInfo: false,
  })
}
