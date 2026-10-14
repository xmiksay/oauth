import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { ApiError } from '@/api/client'
import type { Me } from '@/api/types'
import { ASSERTION_JSON, REQUEST_OPTIONS, domError, fakeMe, stubWebAuthn } from '@/test/helpers'

const api = { reauthOptions: vi.fn() }
vi.mock('@/api/me', () => ({ me: api }))

const { default: ReauthPrompt } = await import('./ReauthPrompt.vue')
const { useAuthStore } = await import('@/stores/auth')

function mountPrompt(over: Partial<Me>, action = vi.fn(async () => {}), slot = '') {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe(over))
  const w = mount(ReauthPrompt, {
    props: { open: true, title: 'T', message: 'M', confirmLabel: 'Continue', action },
    slots: slot ? { default: slot } : {},
    global: { plugins: [pinia] },
    attachTo: document.body,
  })
  return { w, action }
}

const withPasskeys = { mfa: { totp: false, totp_pending: false, recovery_codes_remaining: 0, passkeys: 1 } }
const button = (w: ReturnType<typeof mount>, text: string) =>
  w.findAll('button').find((b) => b.text() === text)

beforeEach(() => api.reauthOptions.mockReset())
afterEach(() => {
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})

describe('ReauthPrompt', () => {
  it('asks only for the password when the user has no passkey', async () => {
    stubWebAuthn()
    const { w, action } = mountPrompt({})
    expect(button(w, 'Use a passkey instead')).toBeUndefined()
    await w.find('#pp-password').setValue('pw')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(action).toHaveBeenCalledWith({ password: 'pw' })
  })

  it('offers a passkey instead of the password and sends its assertion', async () => {
    stubWebAuthn()
    api.reauthOptions.mockResolvedValue(REQUEST_OPTIONS)
    const { w, action } = mountPrompt(withPasskeys)
    await button(w, 'Use a passkey instead')?.trigger('click')
    await flushPromises()
    expect(action).toHaveBeenCalledWith({ passkey: ASSERTION_JSON })
  })

  it('hides the passkey option where the browser has no WebAuthn', () => {
    const { w } = mountPrompt(withPasskeys)
    expect(button(w, 'Use a passkey instead')).toBeUndefined()
    expect(w.find('#pp-password').exists()).toBe(true)
  })

  it('confirms a passkey-only user with a passkey, without a password field', async () => {
    stubWebAuthn()
    api.reauthOptions.mockResolvedValue(REQUEST_OPTIONS)
    const { w, action } = mountPrompt({ ...withPasskeys, has_password: false })
    expect(w.find('#pp-password').exists()).toBe(false)
    expect(button(w, 'Continue')?.attributes('disabled')).toBeUndefined()
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(action).toHaveBeenCalledTimes(1)
    expect(action).toHaveBeenCalledWith({ passkey: ASSERTION_JSON })
  })

  it('says the passkey failed on 403 and notes a dismissed dialog softly', async () => {
    const { get } = stubWebAuthn()
    api.reauthOptions.mockResolvedValue(REQUEST_OPTIONS)
    const action = vi.fn(async () => {
      throw new ApiError(403, { error: 'forbidden' })
    })
    const { w } = mountPrompt(withPasskeys, action)
    await button(w, 'Use a passkey instead')?.trigger('click')
    await flushPromises()
    expect(w.find('[role=alert]').text()).toMatch(/passkey couldn't be verified/)

    get.mockRejectedValueOnce(domError('NotAllowedError'))
    await button(w, 'Use a passkey instead')?.trigger('click')
    await flushPromises()
    expect(w.find('[role=alert]').exists()).toBe(false)
    expect(w.find('[role=status]').text()).toBe('The passkey request was cancelled.')
  })

  it("validates the caller's fields before opening the passkey dialog", async () => {
    const { get } = stubWebAuthn()
    const { w, action } = mountPrompt(withPasskeys, undefined, '<input id="extra" required>')
    await button(w, 'Use a passkey instead')?.trigger('click')
    await flushPromises()
    expect(api.reauthOptions).not.toHaveBeenCalled()
    expect(get).not.toHaveBeenCalled()
    expect(action).not.toHaveBeenCalled()
  })

  it('explains a passkey-only user on a browser without passkeys', () => {
    const { w } = mountPrompt({ ...withPasskeys, has_password: false })
    expect(w.find('[role=alert]').text()).toMatch(/can't use them/)
    expect(button(w, 'Continue')).toBeUndefined()
  })
})
