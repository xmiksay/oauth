import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { createPinia } from 'pinia'
import { ApiError } from '@/api/client'
import type { TxView } from '@/api/authn'
import { ASSERTION_JSON, REQUEST_OPTIONS, domError, stubWebAuthn } from '@/test/helpers'

const api = {
  get: vi.fn(),
  password: vi.fn(),
  requestPasswordReset: vi.fn(),
  passkeyOptions: vi.fn(),
  passkey: vi.fn(),
  sendTelegramCode: vi.fn(),
  submitTelegram: vi.fn(),
}
vi.mock('@/api/authn', async (orig) => ({
  ...(await orig<typeof import('@/api/authn')>()),
  authn: api,
}))

const { default: LoginPage } = await import('./LoginPage.vue')

const passwordView: TxView = {
  tx: 'tx-1',
  step: 'password',
  factors: ['password'],
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

beforeEach(() => Object.values(api).forEach((f) => f.mockReset()))
afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
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

  it('sends a Telegram code after a failed delivery and submits it', async () => {
    api.get.mockResolvedValue({
      ...passwordView,
      step: 'mfa',
      factors: ['telegram'],
      user: { email: 'ann@example.com', display_name: 'Ann' },
    })
    api.sendTelegramCode
      .mockRejectedValueOnce(new ApiError(502, { error: 'delivery_failed' }))
      .mockResolvedValueOnce({ sent: true, expires_in: 300 })
    api.submitTelegram.mockRejectedValue(new ApiError(401, { error: 'invalid_code' }))
    const w = await mountPage()
    const send = () =>
      w.findAll('button').find((b) => b.text() === 'Send code via Telegram')?.trigger('click')
    await send()
    await flushPromises()
    expect(w.find('[role=alert]').text()).toBe("Couldn't send the code via Telegram. Try again.")
    await send()
    await flushPromises()
    expect(w.find('[role=status]').text()).toContain('We sent a code to your Telegram.')
    expect(document.activeElement?.id).toBe('telegram-code')
    await w.find('#telegram-code').setValue('123456')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(api.submitTelegram).toHaveBeenCalledWith('tx-1', '123456')
    expect(w.find('[role=alert]').text()).toBe(
      'Wrong or expired code. Request a new code if needed.',
    )
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

describe('LoginPage passkeys', () => {
  const passkeyView: TxView = { ...passwordView, factors: ['password', 'passkey'] }
  const mfaView: TxView = {
    ...passwordView,
    step: 'mfa',
    user: { email: 'ann@example.com', display_name: 'Ann' },
    factors: ['totp', 'recovery'],
  }
  const button = (w: Awaited<ReturnType<typeof mountPage>>, text: string) =>
    w.findAll('button').find((b) => b.text() === text)

  it('offers no passkey where the browser has no WebAuthn', async () => {
    api.get.mockResolvedValue(passkeyView)
    const w = await mountPage()
    expect(button(w, 'Sign in with a passkey')).toBeUndefined()
    expect(w.find('#login-email').attributes('autocomplete')).toBe('username')
  })

  it('cancels the autofill request before the passkey dialog and uses fresh options', async () => {
    const wa = stubWebAuthn(true)
    let autofill: AbortSignal | undefined
    wa.get.mockImplementationOnce(async (o) => {
      autofill = o?.signal ?? undefined
      return new Promise((_, reject) =>
        autofill?.addEventListener('abort', () => reject(domError('AbortError'))),
      )
    })
    api.get.mockResolvedValue(passkeyView)
    api.passkeyOptions.mockResolvedValue(REQUEST_OPTIONS)
    api.passkey.mockResolvedValue(mfaView)
    const w = await mountPage()
    await vi.waitFor(() => expect(wa.get).toHaveBeenCalledTimes(1))
    expect(wa.get.mock.calls[0]?.[0]?.mediation).toBe('conditional')
    expect(w.find('#login-email').attributes('autocomplete')).toBe('username webauthn')

    await button(w, 'Sign in with a passkey')?.trigger('click')
    await flushPromises()
    expect(autofill?.aborted).toBe(true)
    expect(api.passkeyOptions).toHaveBeenCalledTimes(2)
    expect(wa.get.mock.calls[1]?.[0]?.mediation).toBeUndefined()
    expect(api.passkey).toHaveBeenCalledTimes(1)
    expect(api.passkey).toHaveBeenCalledWith('tx-1', ASSERTION_JSON)
    expect(w.find('#mfa-code').exists()).toBe(true)
  })

  it('shows a soft note when the passkey dialog is dismissed', async () => {
    const wa = stubWebAuthn()
    wa.get.mockRejectedValue(domError('NotAllowedError'))
    api.get.mockResolvedValue(passkeyView)
    api.passkeyOptions.mockResolvedValue(REQUEST_OPTIONS)
    const w = await mountPage()
    await button(w, 'Sign in with a passkey')?.trigger('click')
    await flushPromises()
    expect(w.find('[role=status]').text()).toBe('Passkey sign-in was cancelled.')
    expect(w.find('[role=alert]').exists()).toBe(false)
  })

  it('offers only a passkey at the MFA step when that is all the user has', async () => {
    stubWebAuthn()
    api.get.mockResolvedValue({ ...mfaView, factors: ['passkey'] })
    api.passkeyOptions.mockResolvedValue(REQUEST_OPTIONS)
    api.passkey.mockRejectedValue(new ApiError(401, { error: 'invalid_credentials' }))
    const w = await mountPage()
    expect(w.find('#mfa-code').exists()).toBe(false)
    expect(document.activeElement?.textContent?.trim()).toBe('Use a passkey')
    await button(w, 'Use a passkey')?.trigger('click')
    await flushPromises()
    expect(w.find('[role=alert]').text()).toBe(
      "That passkey couldn't be verified. Try again or use another method.",
    )
  })
})

const SENT =
  'If an account exists for that address, we sent a link to reset the password. It expires in 30 minutes.'

async function forgot(w: Awaited<ReturnType<typeof mountPage>>) {
  await w.findAll('button').find((b) => b.text() === 'Forgot password?')?.trigger('click')
  await flushPromises()
}
