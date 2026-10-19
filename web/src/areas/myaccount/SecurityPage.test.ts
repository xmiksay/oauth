import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { fakeMe } from '@/test/helpers'

const api = {
  get: vi.fn(),
  passkeys: vi.fn(),
  getTelegram: vi.fn(),
  identities: vi.fn(),
}
vi.mock('@/api/me', () => ({ me: api }))

const { default: SecurityPage } = await import('./SecurityPage.vue')
const { useAuthStore } = await import('@/stores/auth')

async function mountPage(telegram: boolean) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ features: { email: true, telegram } }))
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/myaccount/security', component: SecurityPage }],
  })
  await router.push('/myaccount/security')
  const w = mount(SecurityPage, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return w
}

const headings = (w: ReturnType<typeof mount>) => w.findAll('h2').map((h) => h.text())

beforeEach(() => {
  Object.values(api).forEach((f) => f.mockReset())
  api.passkeys.mockResolvedValue({ items: [] })
  api.getTelegram.mockResolvedValue({ linked: false, username: null, linked_at: null })
  api.identities.mockResolvedValue({ items: [], available: [] })
})

describe('SecurityPage', () => {
  it('shows the Telegram section only when the server has a bot', async () => {
    const off = await mountPage(false)
    expect(off.text()).not.toContain('Telegram')
    expect(api.getTelegram).not.toHaveBeenCalled()

    const on = await mountPage(true)
    expect(headings(on)).toContain('Telegram')
    expect(api.getTelegram).toHaveBeenCalledTimes(1)
  })

  it('shows linked accounts only when there is a provider to link or one linked', async () => {
    const none = await mountPage(false)
    expect(headings(none)).not.toContain('Linked accounts')

    api.identities.mockResolvedValue({ items: [], available: [{ id: 'idp1', name: 'Entra' }] })
    const some = await mountPage(false)
    expect(headings(some)).toContain('Linked accounts')
  })
})
