import { afterEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

afterEach(() => vi.unstubAllGlobals())

describe('router guard', () => {
  it('sends the dev apex (no tenant label) to the system admin center', async () => {
    const replace = vi.fn()
    vi.stubGlobal('location', {
      ...window.location,
      protocol: 'http:',
      host: 'localhost:5173',
      hostname: 'localhost',
      replace,
    })
    setActivePinia(createPinia())
    const { router } = await import('./index')
    await router.push('/admin/users')
    expect(replace).toHaveBeenCalledWith('http://system.localhost:5173/admin')
    expect(router.currentRoute.value.path).not.toBe('/admin/users')
  })
})
