import { describe, expect, it } from 'vitest'
import { fakeIdp } from '@/test/helpers'
import {
  changedIdpFields,
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
      enabled: true,
      visible: true,
    })
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
