import { afterEach, describe, expect, it, vi } from 'vitest'
import { mockFetch } from '@/test/helpers'
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

  it('tells a step view from a redirect', () => {
    expect(isRedirect({ redirect: 'x' })).toBe(true)
    expect(
      isRedirect({
        tx: 'x',
        step: 'password',
        tenant: { slug: 't', display_name: 'T' },
        client: { client_id: 'c', display_name: 'C' },
        user: null,
        consent: null,
      }),
    ).toBe(false)
  })
})
