import { describe, expect, it } from 'vitest'
import { buildOidcSettings, createUserManager, SPA_SCOPE } from './oidc'

describe('buildOidcSettings', () => {
  it('builds admin-portal settings for a tenant', () => {
    const s = buildOidcSettings('contoso', 'admin', 'https://id.example.com')
    expect(s).toMatchObject({
      authority: 'https://id.example.com/contoso',
      client_id: 'admin-portal',
      redirect_uri: 'https://id.example.com/contoso/admin/callback',
      post_logout_redirect_uri: 'https://id.example.com/contoso/admin',
      response_type: 'code',
      scope: SPA_SCOPE,
    })
  })

  it('builds my-account settings for a tenant', () => {
    const s = buildOidcSettings('contoso', 'myaccount', 'https://id.example.com')
    expect(s.client_id).toBe('my-account')
    expect(s.redirect_uri).toBe('https://id.example.com/contoso/myaccount/callback')
    expect(s.post_logout_redirect_uri).toBe('https://id.example.com/contoso/myaccount')
  })

  it('defaults to the current origin', () => {
    const s = buildOidcSettings('system', 'admin')
    expect(s.authority).toBe(`${window.location.origin}/system`)
  })

  it('requests the management API delegated scope by its identifier URI', () => {
    // Must match `directory/builtin_apps.rs` (identifier_uri api://management-api) and
    // docs/api/management.md.
    expect(SPA_SCOPE.split(' ')).toEqual([
      'openid',
      'offline_access',
      'api://management-api/Directory.AccessAsUser',
    ])
  })
})

describe('createUserManager', () => {
  it('keeps tokens and PKCE state in sessionStorage, never localStorage', async () => {
    localStorage.clear()
    sessionStorage.clear()
    const m = createUserManager('contoso', 'admin')
    expect(m.settings.automaticSilentRenew).toBe(false)
    expect(m.settings.monitorSession).toBe(false)
    await m.settings.userStore.set('probe', 'x')
    await m.settings.stateStore.set('probe-state', 'y')
    expect(Object.keys(sessionStorage).some((k) => k.includes('probe'))).toBe(true)
    expect(localStorage.length).toBe(0)
  })
})
