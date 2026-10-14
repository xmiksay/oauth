import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { createPinia } from 'pinia'
import { ApiError } from '@/api/client'
import type { TxView } from '@/api/authn'

const api = { get: vi.fn(), password: vi.fn() }
vi.mock('@/api/authn', async (orig) => ({
  ...(await orig<typeof import('@/api/authn')>()),
  authn: api,
}))

const { default: LoginPage } = await import('./LoginPage.vue')

const passwordView: TxView = {
  tx: 'tx-1',
  step: 'password',
  tenant: { slug: 'contoso', display_name: 'Contoso' },
  client: { client_id: 'shop', display_name: 'Shop' },
  user: null,
  consent: null,
}

async function mountPage() {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/login', component: LoginPage }],
  })
  await router.push('/login?tx=tx-1')
  const w = mount(LoginPage, {
    global: { plugins: [createPinia(), router] },
    attachTo: document.body,
  })
  await flushPromises()
  return w
}

beforeEach(() => {
  api.get.mockReset()
  api.password.mockReset()
})
afterEach(() => {
  vi.useRealTimers()
  document.body.innerHTML = ''
})

describe('LoginPage', () => {
  it('offers "Try again" when the transaction fails to load, then focuses the form', async () => {
    api.get.mockRejectedValueOnce(new TypeError('Failed to fetch')).mockResolvedValueOnce(passwordView)
    const w = await mountPage()
    expect(w.find('[role=alert]').text()).toMatch(/reach the server/)
    await w.findAll('button').find((b) => b.text() === 'Try again')?.trigger('click')
    await flushPromises()
    expect(w.find('#login-email').exists()).toBe(true)
    expect(document.activeElement?.id).toBe('login-email')
  })

  it('announces the rate limit once and ticks the countdown outside the live region', async () => {
    vi.useFakeTimers()
    api.get.mockResolvedValue(passwordView)
    api.password.mockRejectedValue(new ApiError(429, { error: 'rate_limited' }, 5))
    const w = await mountPage()
    await w.find('#login-email').setValue('a@b.c')
    await w.find('#login-password').setValue('pw')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.find('[role=alert]').text()).toBe('Too many attempts. Please wait before trying again.')
    const countdown = w.find('[data-testid=retry-countdown]')
    expect(countdown.attributes('aria-live')).toBe('off')
    expect(countdown.text()).toBe('Try again in 5 s.')
    vi.advanceTimersByTime(2000)
    await flushPromises()
    expect(w.find('[data-testid=retry-countdown]').text()).toBe('Try again in 3 s.')
    expect(w.find('button[type=submit]').attributes('disabled')).toBeDefined()
  })
})
