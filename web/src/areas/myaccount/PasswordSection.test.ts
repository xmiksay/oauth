import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { ApiError } from '@/api/client'
import type { Me } from '@/api/types'
import { ASSERTION_JSON, REQUEST_OPTIONS, fakeMe, stubWebAuthn } from '@/test/helpers'

const api = { changePassword: vi.fn(), reauthOptions: vi.fn(), get: vi.fn() }
vi.mock('@/api/me', () => ({ me: api }))

const { default: PasswordSection } = await import('./PasswordSection.vue')
const { useAuthStore } = await import('@/stores/auth')

function mountSection(over: Partial<Me> = {}) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe(over))
  return mount(PasswordSection, { global: { plugins: [pinia] } })
}

async function fill(w: ReturnType<typeof mountSection>, next = 'a-long-new-password') {
  await w.find('#pw-new').setValue(next)
  await w.find('#pw-confirm').setValue(next)
  await w.find('form').trigger('submit')
  await flushPromises()
}

beforeEach(() => Object.values(api).forEach((f) => f.mockReset()))
afterEach(() => vi.unstubAllGlobals())

describe('PasswordSection', () => {
  it('changes the password with the current one', async () => {
    api.changePassword
      .mockRejectedValueOnce(new ApiError(403, { error: 'forbidden' }))
      .mockResolvedValueOnce(undefined)
    const w = mountSection()
    await w.find('#pw-current').setValue('old')
    await fill(w)
    expect(api.changePassword).toHaveBeenCalledWith('a-long-new-password', { password: 'old' })
    expect(w.find('[role=alert]').text()).toBe('Your current password is incorrect.')
    await w.find('#pw-current').setValue('old')
    await fill(w)
    expect(w.find('[role=status]').text()).toContain('Password changed.')
  })

  it('lets a passkey-only user set a first password, confirmed with a passkey', async () => {
    stubWebAuthn()
    api.reauthOptions.mockResolvedValue(REQUEST_OPTIONS)
    api.changePassword.mockResolvedValue(undefined)
    api.get.mockResolvedValue(fakeMe())
    const w = mountSection({ has_password: false })
    expect(w.find('h2').text()).toBe('Set a password')
    expect(w.find('#pw-current').exists()).toBe(false)
    await fill(w)
    expect(api.changePassword).toHaveBeenCalledWith('a-long-new-password', {
      passkey: ASSERTION_JSON,
    })
    expect(w.find('[role=status]').text()).toContain('Password set.')
    expect(useAuthStore().me?.has_password).toBe(true)
    expect(w.find('h2').text()).toBe('Password')
  })

  it('blocks setting a password where the browser has no passkeys', () => {
    const w = mountSection({ has_password: false })
    expect(w.find('[role=alert]').text()).toMatch(/can't use passkeys/)
    expect(w.find('button[type=submit]').attributes('disabled')).toBeDefined()
  })
})
