import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { createPinia } from 'pinia'
import { ApiError } from '@/api/client'
import type { TxView } from '@/api/authn'

const api = { get: vi.fn(), password: vi.fn(), requestPasswordReset: vi.fn() }
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
  features: { password_reset: false },
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
  api.requestPasswordReset.mockReset()
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

  it('hides "Forgot password?" when the server cannot send email', async () => {
    api.get.mockResolvedValue(passwordView)
    const w = await mountPage()
    expect(w.text()).not.toContain('Forgot password?')
  })

  it('requests a reset link with the typed email, then returns to the same tx', async () => {
    api.get.mockResolvedValue({ ...passwordView, features: { password_reset: true } })
    api.requestPasswordReset.mockResolvedValue({ accepted: true })
    const w = await mountPage()
    await w.find('#login-email').setValue(' ann@example.com ')
    await forgot(w)
    expect(w.find('h1').text()).toBe('Reset your password')
    expect((w.find('#forgot-email').element as HTMLInputElement).value).toBe('ann@example.com')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(api.requestPasswordReset).toHaveBeenCalledWith('ann@example.com')
    expect(w.text()).toContain(SENT)
    await w.findAll('button').find((b) => b.text() === 'Back to sign in')?.trigger('click')
    await flushPromises()
    expect((w.find('#login-email').element as HTMLInputElement).value).toBe('ann@example.com')
    expect(api.get).toHaveBeenCalledTimes(1)
  })

  it('says the same thing whatever the address', async () => {
    api.get.mockResolvedValue({ ...passwordView, features: { password_reset: true } })
    api.requestPasswordReset.mockResolvedValue({ accepted: true })
    const texts: string[] = []
    for (const email of ['known@example.com', 'nobody@example.com']) {
      const w = await mountPage()
      await forgot(w)
      await w.find('#forgot-email').setValue(email)
      await w.find('form').trigger('submit')
      await flushPromises()
      texts.push(w.find('[aria-live=polite]').text())
      w.unmount()
    }
    expect(texts[0]).toContain(SENT)
    expect(texts[1]).toBe(texts[0])
  })

  it('shows the rate limit on the reset form', async () => {
    api.get.mockResolvedValue({ ...passwordView, features: { password_reset: true } })
    api.requestPasswordReset.mockRejectedValue(new ApiError(429, { error: 'rate_limited' }, 60))
    const w = await mountPage()
    await forgot(w)
    await w.find('#forgot-email').setValue('a@b.c')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.find('[role=alert]').text()).toBe('Too many attempts. Try again in 60 seconds.')
  })
})

const SENT =
  'If an account exists for that address, we sent a link to reset the password. It expires in 30 minutes.'

async function forgot(w: Awaited<ReturnType<typeof mountPage>>) {
  await w.findAll('button').find((b) => b.text() === 'Forgot password?')?.trigger('click')
  await flushPromises()
}
