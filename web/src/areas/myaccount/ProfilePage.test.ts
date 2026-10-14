import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { Me } from '@/api/types'

const api = { update: vi.fn(), changePassword: vi.fn(), sendVerification: vi.fn(), changeEmail: vi.fn(), get: vi.fn() }
vi.mock('@/api/me', () => ({ me: api }))

const { default: ProfilePage } = await import('./ProfilePage.vue')
const { useAuthStore } = await import('@/stores/auth')

function me(over: Partial<Me> = {}): Me {
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
    mfa: { totp: false, totp_pending: false, recovery_codes_remaining: 0 },
    features: { email: true },
    ...over,
  }
}

beforeEach(() => Object.values(api).forEach((f) => f.mockReset()))

describe('ProfilePage', () => {
  it('keeps the email section after a rename (PATCH me returns the full me shape)', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    useAuthStore().setMe(me())
    api.update.mockResolvedValue(me({ display_name: 'Ann Renamed' }))
    const w = mount(ProfilePage, { global: { plugins: [pinia] } })
    const nameInput = w.findAll('input').find((i) => (i.element as HTMLInputElement).value === 'Ann')
    await nameInput?.setValue('Ann Renamed')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(api.update).toHaveBeenCalledWith({ display_name: 'Ann Renamed' })
    expect(useAuthStore().me?.display_name).toBe('Ann Renamed')
    const buttons = w.findAll('button').map((b) => b.text())
    expect(buttons).toContain('Change email')
    expect(buttons).toContain('Send verification link')
  })
})
