import { describe, expect, it } from 'vitest'
import { buildOidcSettings, createUserManager, SPA_SCOPE } from './oidc'

describe('buildOidcSettings', () => {
  it('builds admin-portal settings on the tenant origin', () => {
    const s = buildOidcSettings('admin', 'https://contoso.id.example.com')
    expect(s).toMatchObject({
      authority: 'https://contoso.id.example.com',
      client_id: 'admin-portal',
      redirect_uri: 'https://contoso.id.example.com/admin/callback',
      post_logout_redirect_uri: 'https://contoso.id.example.com/admin',
      response_type: 'code',
      scope: SPA_SCOPE,
    })
  })

  it('builds my-account settings on the tenant origin', () => {
    const s = buildOidcSettings('myaccount', 'https://contoso.id.example.com')
    expect(s.client_id).toBe('my-account')
    expect(s.redirect_uri).toBe('https://contoso.id.example.com/myaccount/callback')
    expect(s.post_logout_redirect_uri).toBe('https://contoso.id.example.com/myaccount')
  })

  it('defaults to the current origin', () => {
    const s = buildOidcSettings('admin')
    expect(s.authority).toBe(window.location.origin)
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
    const m = createUserManager('admin')
    expect(m.settings.automaticSilentRenew).toBe(false)
    expect(m.settings.monitorSession).toBe(false)
    await m.settings.userStore.set('probe', 'x')
    await m.settings.stateStore.set('probe-state', 'y')
    expect(Object.keys(sessionStorage).some((k) => k.includes('probe'))).toBe(true)
    expect(localStorage.length).toBe(0)
  })
})
