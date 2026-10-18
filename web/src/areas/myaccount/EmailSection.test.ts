import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { ApiError } from '@/api/client'
import type { Me } from '@/api/types'

const api = { sendVerification: vi.fn(), changeEmail: vi.fn(), get: vi.fn() }
vi.mock('@/api/me', () => ({ me: api }))

const { default: EmailSection } = await import('./EmailSection.vue')
const { useAuthStore } = await import('@/stores/auth')

function detail(over: Partial<Me> = {}): Me {
  return {
    id: 'u',
    email: 'ann@example.com',
    display_name: 'Ann',
    user_type: 'member',
    email_verified: false,
    disabled: false,
    must_change_password: false,
    has_password: true,
    created_at: '',
    updated_at: '',
    directory_roles: [],
    mfa: { totp: false, totp_pending: false, recovery_codes_remaining: 0, passkeys: 0, telegram: false },
    features: { email: true, telegram: false },
    ...over,
  }
}

function mountSection(over: Partial<Me> = {}) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(detail(over))
  return mount(EmailSection, { global: { plugins: [pinia] } })
}

const button = (w: ReturnType<typeof mountSection>, text: string) =>
  w.findAll('button').find((b) => b.text() === text)

beforeEach(() => Object.values(api).forEach((f) => f.mockReset()))

describe('EmailSection', () => {
  it('sends a verification link for an unverified address', async () => {
    api.sendVerification.mockResolvedValue({ sent: true })
    const w = mountSection()
    expect(w.find('[data-testid=email-status]').text()).toBe('Unverified')
    await button(w, 'Send verification link')?.trigger('click')
    await flushPromises()
    expect(w.find('[role=status]').text()).toContain('Check your inbox')
  })

  it('refreshes instead of erroring when the address was verified meanwhile', async () => {
    api.sendVerification.mockRejectedValue(new ApiError(409, { error: 'conflict' }))
    api.get.mockResolvedValue(detail({ email_verified: true }))
    const w = mountSection()
    await button(w, 'Send verification link')?.trigger('click')
    await flushPromises()
    expect(w.find('[data-testid=email-status]').text()).toBe('Verified')
    expect(w.find('[role=alert]').exists()).toBe(false)
    expect(button(w, 'Send verification link')).toBeUndefined()
  })

  it('changes the email with the current password and explains the pending link', async () => {
    api.changeEmail.mockResolvedValue({ sent: true })
    const w = mountSection({ email_verified: true })
    await button(w, 'Change email')?.trigger('click')
    await flushPromises()
    await w.find('#ce-email').setValue(' new@example.com ')
    await w.find('#pp-password').setValue('pw')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(api.changeEmail).toHaveBeenCalledWith('new@example.com', { password: 'pw' })
    expect(w.find('[role=status]').text()).toBe(
      'We sent a link to new@example.com. Your email changes when you open it.',
    )
  })

  it('maps a taken address and a wrong password', async () => {
    api.changeEmail
      .mockRejectedValueOnce(new ApiError(409, { error: 'conflict' }))
      .mockRejectedValueOnce(new ApiError(403, { error: 'forbidden' }))
    const w = mountSection()
    await button(w, 'Change email')?.trigger('click')
    await flushPromises()
    await w.find('#ce-email').setValue('taken@example.com')
    for (const msg of [/already used by another account/, /current password is incorrect/]) {
      await w.find('#pp-password').setValue('pw')
      await w.find('form').trigger('submit')
      await flushPromises()
      expect(w.find('[role=alert]').text()).toMatch(msg)
    }
  })

  it('offers neither action when the server cannot send email', () => {
    const w = mountSection({ features: { email: false, telegram: false } })
    expect(w.findAll('button')).toHaveLength(0)
  })
})
