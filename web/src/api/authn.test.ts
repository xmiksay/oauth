import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  ASSERTION_JSON,
  CREATION_OPTIONS,
  REGISTRATION_JSON,
  REQUEST_OPTIONS,
  mockFetch,
} from '@/test/helpers'
import { authn, isRedirect } from './authn'

afterEach(() => vi.unstubAllGlobals())

describe('login API client', () => {
  it('posts JSON steps with same-origin credentials', async () => {
    const fetchCalls = mockFetch({ body: { redirect: 'https://app/cb?code=1' } })
    const res = await authn.password('tx-1', 'a@b.c', 'pw')
    expect(isRedirect(res)).toBe(true)
    expect(fetchCalls[0]).toMatchObject({
      url: '/api/authn/tx/tx-1/password',
      method: 'POST',
      body: { email: 'a@b.c', password: 'pw' },
    })
    expect(fetchCalls[0]?.headers['Content-Type']).toBe('application/json')
    const init = vi.mocked(fetch).mock.calls[0]?.[1]
    expect(init?.credentials).toBe('same-origin')
  })

  it('sends all scopes when approving and none when declining', async () => {
    const calls = mockFetch({}, {})
    await authn.consent('x', true, ['A', 'B'])
    await authn.consent('x', false, ['A'])
    expect(calls[0]?.body).toEqual({ approve: true, scopes: ['A', 'B'] })
    expect(calls[1]?.body).toEqual({ approve: false })
  })

  it('signs out with an empty JSON body', async () => {
    const calls = mockFetch({ body: { signed_out: true } })
    await authn.signOut()
    expect(calls[0]).toMatchObject({ url: '/oauth2/logout', method: 'POST', body: {} })
  })

  it('posts the email-link endpoints outside any transaction', async () => {
    const calls = mockFetch({ status: 202, body: { accepted: true } }, {}, {}, {})
    await authn.requestPasswordReset('a@b.c')
    await authn.verifyEmail('tok')
    await authn.resetPassword('tok', 'pw')
    await authn.acceptInvite('tok', 'pw')
    expect(calls.map((c) => [c.url, c.body])).toEqual([
      ['/api/authn/password-reset', { email: 'a@b.c' }],
      ['/api/authn/email/verify', { token: 'tok' }],
      ['/api/authn/email/reset', { token: 'tok', new_password: 'pw' }],
      ['/api/authn/email/invite', { token: 'tok', new_password: 'pw' }],
    ])
    expect(calls.every((c) => c.method === 'POST')).toBe(true)
  })

  it('posts the passkey endpoints of a transaction and of an invitation', async () => {
    const calls = mockFetch({ body: REQUEST_OPTIONS }, {}, { body: CREATION_OPTIONS }, {})
    expect(await authn.passkeyOptions('tx-1')).toEqual(REQUEST_OPTIONS)
    await authn.passkey('tx-1', ASSERTION_JSON)
    expect(await authn.invitePasskeyOptions('tok')).toEqual(CREATION_OPTIONS)
    await authn.acceptInviteWithPasskey('tok', REGISTRATION_JSON)
    expect(calls.map((c) => [c.method, c.url, c.body])).toEqual([
      ['POST', '/api/authn/tx/tx-1/passkey/options', {}],
      ['POST', '/api/authn/tx/tx-1/passkey', ASSERTION_JSON],
      ['POST', '/api/authn/email/invite/passkey/options', { token: 'tok' }],
      ['POST', '/api/authn/email/invite/passkey', { token: 'tok', credential: REGISTRATION_JSON }],
    ])
  })

  it('sends a Telegram code with {} and posts it like a TOTP code', async () => {
    const calls = mockFetch({ body: { sent: true, expires_in: 300 } }, {})
    expect(await authn.sendTelegramCode('tx-1')).toEqual({ sent: true, expires_in: 300 })
    await authn.submitTelegram('tx-1', '123456')
    expect(calls.map((c) => [c.method, c.url, c.body])).toEqual([
      ['POST', '/api/authn/tx/tx-1/telegram/send', {}],
      ['POST', '/api/authn/tx/tx-1/telegram', { code: '123456' }],
    ])
  })

  it('tells a step view from a redirect', () => {
    expect(isRedirect({ redirect: 'x' })).toBe(true)
    expect(
      isRedirect({
        tx: 'x',
        step: 'password',
        factors: ['password'],
        tenant: { slug: 't', display_name: 'T' },
        client: { client_id: 'c', display_name: 'C' },
        user: null,
        consent: null,
        features: { password_reset: false },
      }),
    ).toBe(false)
  })
})
