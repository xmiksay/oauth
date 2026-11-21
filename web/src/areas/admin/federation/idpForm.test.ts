import { describe, expect, it } from 'vitest'
import { fakeIdp } from '@/test/helpers'
import {
  applyPreset,
  changedIdpFields,
  entraUrls,
  formState,
  lockoutWarning,
  relinkWarning,
  toInput,
  words,
} from './idpForm'

const IDP = fakeIdp()

describe('idpForm', () => {
  it('starts a new provider with the server defaults', () => {
    expect(toInput(formState())).toEqual({
      kind: 'oidc',
      name: '',
      issuer: '',
      discovery_url: null,
      client_id: '',
      client_auth: 'post',
      scopes: ['openid', 'email', 'profile'],
      policy: 'link_only',
      trust_upstream_mfa: false,
      mfa_acr: null,
      email_domains: [],
      hosted_domain: null,
      allowed_tenants: [],
      trust_upstream_email: false,
      enabled: true,
      visible: true,
    })
  })

  it('applies presets, keeping a typed name', () => {
    const f = formState()
    applyPreset(f, 'google')
    expect(f).toMatchObject({ kind: 'google', name: 'Google', issuer: 'https://accounts.google.com' })
    applyPreset(f, 'github')
    expect(f).toMatchObject({ name: 'GitHub', scopes: 'read:user user:email', issuer: 'https://github.com' })
    f.name = 'Our GitHub'
    applyPreset(f, 'oidc')
    expect(f).toMatchObject({ kind: 'oidc', name: 'Our GitHub', issuer: '', scopes: 'openid email profile' })
  })

  it('derives Entra URLs from the directory', () => {
    expect(entraUrls(' 9188040D-6C67-4C5B-B112-36A304B66DAD ')).toEqual({
      issuer: 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
      discovery_url: '',
    })
    expect(entraUrls('common')).toEqual({
      issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
      discovery_url: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    })
    expect(entraUrls('contoso')).toBeNull()
  })

  it('sends kind-specific fields only for their kind', () => {
    const f = {
      ...formState(),
      hosted_domain: 'contoso.com',
      allowed_tenants: 'a, b',
      trust_upstream_email: true,
    }
    expect(toInput(f)).toMatchObject({ hosted_domain: null, allowed_tenants: [], trust_upstream_email: true })
    expect(toInput({ ...f, kind: 'google' }).hosted_domain).toBe('contoso.com')
    const multi = { ...f, kind: 'entra' as const, issuer: 'https://x/{tenantid}/v2.0' }
    expect(toInput(multi).allowed_tenants).toEqual(['a', 'b'])
    expect(toInput({ ...f, kind: 'github' }).trust_upstream_email).toBe(false)
  })

  it('splits lists on commas and whitespace', () => {
    expect(words(' a.com, b.com\nc.com,,')).toEqual(['a.com', 'b.com', 'c.com'])
  })

  it('round-trips a provider without changes', () => {
    expect(changedIdpFields(IDP, toInput(formState(IDP)))).toEqual({})
  })

  it('keeps only changed fields, and the write-only secret either way', () => {
    const f = { ...formState(IDP), email_domains: 'contoso.com fabrikam.com', mfa_acr: ' ' }
    expect(changedIdpFields(IDP, { ...toInput(f), client_secret: null })).toEqual({
      email_domains: ['contoso.com', 'fabrikam.com'],
      client_secret: null,
    })
  })

  it('warns only when users depend on the provider', () => {
    expect(lockoutWarning(0)).toBeNull()
    expect(lockoutWarning(1)).toMatch(/^1 user can sign in only through this provider\./)
    expect(lockoutWarning(3)).toMatch(/^3 users can .* resets their password or sends an invitation\.$/)
  })

  it('warns about unlinking only for identity changes with linked users', () => {
    expect(relinkWarning({ name: 'x' }, 2)).toBeNull()
    expect(relinkWarning({ issuer: 'https://x' }, 0)).toBeNull()
    expect(relinkWarning({ client_id: 'c' }, 1)).toBe(
      'Changing the issuer, client ID or discovery URL unlinks the 1 linked user; they must link again.',
    )
    expect(relinkWarning({ client_id: 'c' }, 0, true)).toBeNull()
    expect(relinkWarning({ discovery_url: 'https://d' }, 0, true)).toBe(
      'The stored client secret is removed too; enter the secret for the new provider.',
    )
    expect(relinkWarning({ issuer: 'https://x', client_secret: 's' }, 0, true)).toBeNull()
    expect(relinkWarning({ issuer: 'https://x' }, 2, true)).toMatch(
      /unlinks all 2 linked users; they must link again\. The stored client secret is removed too/,
    )
  })
})
