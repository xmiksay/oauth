import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { FakeManager, fakeUser, mockFetch } from '@/test/helpers'

vi.mock('@/auth/oidc', () => ({
  createUserManager: (a: string) => {
    const m = new FakeManager(a)
    m.stored = fakeUser({ access_token: 'tok' })
    return m
  },
}))

const { useAuthStore } = await import('@/stores/auth')
const { identityProviders } = await import('./identityProviders')
const { users } = await import('./directory')
const { me } = await import('./me')

const T = '/api/v1'

beforeEach(async () => {
  setActivePinia(createPinia())
  await useAuthStore().ensureSignedIn('admin', '/')
})
afterEach(() => vi.unstubAllGlobals())

describe('identity provider resources', () => {
  it('pages without search and manages one provider by escaped id', async () => {
    const calls = mockFetch(
      { body: { items: [], next_cursor: null } },
      { status: 201, body: { id: 'i' } },
      { body: { id: 'i' } },
      { body: { id: 'i' } },
      { status: 204 },
    )
    await identityProviders.list({ limit: 25, cursor: 'c1', search: 'x' })
    await identityProviders.create({ name: 'E', issuer: 'https://i', client_id: 'c' })
    await identityProviders.get('a/b')
    await identityProviders.update('a/b', { client_secret: null })
    await identityProviders.remove('a/b')
    expect(calls.map((c) => [c.method, c.url, c.body])).toEqual([
      ['GET', `${T}/identity-providers?limit=25&cursor=c1`, undefined],
      ['POST', `${T}/identity-providers`, { name: 'E', issuer: 'https://i', client_id: 'c' }],
      ['GET', `${T}/identity-providers/a%2Fb`, undefined],
      ['PATCH', `${T}/identity-providers/a%2Fb`, { client_secret: null }],
      ['DELETE', `${T}/identity-providers/a%2Fb`, undefined],
    ])
    expect(calls[0]?.headers.Authorization).toBe('Bearer tok')
  })

  it("unlinks a user's identity", async () => {
    const calls = mockFetch({ status: 204 })
    await users.unlinkIdentity('u1', 'li 1')
    expect(calls[0]).toMatchObject({ method: 'DELETE', url: `${T}/users/u1/identities/li%201` })
  })
})

describe('me identities', () => {
  it('lists, links and unlinks with the re-auth in the body', async () => {
    const calls = mockFetch(
      { body: { items: [], available: [] } },
      { body: { redirect: 'https://idp/authorize' } },
      { status: 204 },
    )
    await me.identities()
    expect(await me.linkIdentity('idp1', { password: 'pw' })).toEqual({
      redirect: 'https://idp/authorize',
    })
    await me.unlinkIdentity('li1', { password: 'pw' })
    expect(calls.map((c) => [c.method, c.url, c.body])).toEqual([
      ['GET', `${T}/me/identities`, undefined],
      ['POST', `${T}/me/identities/idp1/link`, { password: 'pw' }],
      ['DELETE', `${T}/me/identities/li1`, { password: 'pw' }],
    ])
  })
})
