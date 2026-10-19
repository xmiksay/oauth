import { afterEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { FakeManager } from '@/test/helpers'

vi.mock('@/auth/oidc', () => ({
  createUserManager: (a: string) => new FakeManager(a),
}))

afterEach(() => vi.unstubAllGlobals())

function stubHost(host: string) {
  const replace = vi.fn()
  vi.stubGlobal('location', {
    ...window.location,
    protocol: 'http:',
    host,
    hostname: host.split(':')[0],
    replace,
  })
  return replace
}

describe('router guard', () => {
  it('sends the dev apex (no tenant label) to the system admin center', async () => {
    const replace = stubHost('localhost:5173')
    setActivePinia(createPinia())
    const { router } = await import('./index')
    await router.push('/admin/users')
    expect(replace).toHaveBeenCalledWith('http://system.localhost:5173/admin')
    expect(router.currentRoute.value.path).not.toBe('/admin/users')
  })

  it('signs in to the portal with the My Account client and comes back to /', async () => {
    stubHost('contoso.localhost:5173')
    setActivePinia(createPinia())
    FakeManager.instances = []
    const { router } = await import('./index')
    await router.push('/')
    expect(FakeManager.instances.map((m) => m.area)).toEqual(['myaccount'])
    expect(FakeManager.instances[0]?.signinRedirect).toHaveBeenCalledWith({
      state: { returnTo: '/' },
    })
  })
})
