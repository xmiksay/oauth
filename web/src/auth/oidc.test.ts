import { describe, expect, it } from 'vitest'
import { buildOidcSettings, SPA_SCOPE } from './oidc'

describe('buildOidcSettings', () => {
  it('builds admin-portal settings for a tenant', () => {
    const s = buildOidcSettings('contoso', 'admin', 'https://id.example.com')
    expect(s).toMatchObject({
      authority: 'https://id.example.com/contoso',
      client_id: 'admin-portal',
      redirect_uri: 'https://id.example.com/contoso/admin/callback',
      response_type: 'code',
      scope: SPA_SCOPE,
    })
  })

  it('builds my-account settings for a tenant', () => {
    const s = buildOidcSettings('contoso', 'myaccount', 'https://id.example.com')
    expect(s.client_id).toBe('my-account')
    expect(s.redirect_uri).toBe('https://id.example.com/contoso/myaccount/callback')
  })

  it('defaults to the current origin', () => {
    const s = buildOidcSettings('system', 'admin')
    expect(s.authority).toBe(`${window.location.origin}/system`)
  })

  it('requests the management API delegated scope', () => {
    expect(SPA_SCOPE.split(' ')).toEqual([
      'openid',
      'profile',
      'offline_access',
      'api://management/Directory.AccessAsUser',
    ])
  })
})
