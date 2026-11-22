import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { DirectoryRole, Tenant } from '@/api/types'
import { fakeMe } from '@/test/helpers'

const settings = { get: vi.fn(), update: vi.fn() }
vi.mock('@/api/access', () => ({ settings }))

const { default: TenantSettings } = await import('./TenantSettings.vue')
const { useAuthStore } = await import('@/stores/auth')

const TENANT: Tenant = {
  id: 't1',
  slug: 'contoso',
  display_name: 'Contoso',
  is_system: false,
  disabled: false,
  audit_retention_days: 90,
  mfa_policy: 'optional',
  logout_revokes_refresh_tokens: true,
  created_at: '',
  updated_at: '',
}

async function mountPage(roles: DirectoryRole[]) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ directory_roles: roles }))
  settings.get.mockResolvedValue(TENANT)
  const w = mount(TenantSettings, { global: { plugins: [pinia] } })
  await flushPromises()
  return w
}

beforeEach(() => {
  Object.values(settings).forEach((f) => f.mockReset())
})

describe('TenantSettings', () => {
  it('sends only a changed MFA policy', async () => {
    const w = await mountPage(['GlobalAdmin'])
    const select = w.find('#ts-mfa')
    expect((select.element as HTMLSelectElement).value).toBe('optional')
    settings.update.mockResolvedValue({ ...TENANT, mfa_policy: 'required' })
    await select.setValue('required')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(settings.update).toHaveBeenCalledWith({ mfa_policy: 'required' })
    expect(w.text()).toContain('Saved.')
  })

  it('sends the logout revocation toggle when changed', async () => {
    const w = await mountPage(['GlobalAdmin'])
    const box = w.find('#ts-logout-revokes')
    expect((box.element as HTMLInputElement).checked).toBe(true)
    settings.update.mockResolvedValue({ ...TENANT, logout_revokes_refresh_tokens: false })
    await box.setValue(false)
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(settings.update).toHaveBeenCalledWith({ logout_revokes_refresh_tokens: false })
  })

  it('disables the MFA policy without GlobalAdmin', async () => {
    const w = await mountPage(['UserAdmin'])
    expect(w.find('#ts-mfa').attributes('disabled')).toBeDefined()
    expect(w.find('#ts-logout-revokes').attributes('disabled')).toBeDefined()
    expect(w.find('button[type=submit]').exists()).toBe(false)
  })
})
