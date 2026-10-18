import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { fakeMe } from '@/test/helpers'

const api = {
  get: vi.fn(),
  passkeys: vi.fn(),
  getTelegram: vi.fn(),
}
vi.mock('@/api/me', () => ({ me: api }))

const { default: SecurityPage } = await import('./SecurityPage.vue')
const { useAuthStore } = await import('@/stores/auth')

async function mountPage(telegram: boolean) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ features: { email: true, telegram } }))
  const w = mount(SecurityPage, { global: { plugins: [pinia] } })
  await flushPromises()
  return w
}

beforeEach(() => {
  Object.values(api).forEach((f) => f.mockReset())
  api.passkeys.mockResolvedValue({ items: [] })
  api.getTelegram.mockResolvedValue({ linked: false, username: null, linked_at: null })
})

describe('SecurityPage', () => {
  it('shows the Telegram section only when the server has a bot', async () => {
    const off = await mountPage(false)
    expect(off.text()).not.toContain('Telegram')
    expect(api.getTelegram).not.toHaveBeenCalled()

    const on = await mountPage(true)
    expect(on.findAll('h2').map((h) => h.text())).toContain('Telegram')
    expect(api.getTelegram).toHaveBeenCalledTimes(1)
  })
})
