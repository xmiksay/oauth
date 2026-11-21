import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { Application, DirectoryRole } from '@/api/types'
import { fakeMe } from '@/test/helpers'

const applications = { get: vi.fn(), update: vi.fn() }
vi.mock('@/api/applications', () => ({ applications }))

const { default: AppAssignment } = await import('./AppAssignment.vue')
const { useAuthStore } = await import('@/stores/auth')
const { useApplicationStore } = await import('@/stores/application')

function fakeApp(over: Partial<Application> = {}): Application {
  return {
    id: 'a1',
    client_id: 'hr',
    display_name: 'HR',
    client_type: 'confidential',
    builtin: false,
    redirect_uris: [],
    post_logout_redirect_uris: [],
    web_origins: [],
    effective_web_origins: [],
    identifier_uri: null,
    audience: 'api://hr',
    access_token_format: 'jwt',
    signing_alg: 'RS256',
    groups_claim_format: 'id',
    assignment_required: false,
    device_code_enabled: false,
    access_token_ttl_secs: 3600,
    refresh_token_ttl_secs: 86400,
    created_at: '',
    updated_at: '',
    ...over,
  }
}

async function mountForm(app: Application, roles: DirectoryRole[] = ['ApplicationAdmin']) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ directory_roles: roles }))
  applications.get.mockResolvedValue(app)
  await useApplicationStore().load(app.id)
  const w = mount(AppAssignment, { global: { plugins: [pinia] } })
  await flushPromises()
  return w
}

beforeEach(() => {
  Object.values(applications).forEach((f) => f.mockReset())
})

describe('AppAssignment', () => {
  it('turns assignment on, sending only that field', async () => {
    const w = await mountForm(fakeApp())
    const box = w.find<HTMLInputElement>('#as-required')
    expect(box.element.checked).toBe(false)
    expect(w.find('button[type=submit]').attributes('disabled')).toBeDefined()

    applications.update.mockResolvedValue(fakeApp({ assignment_required: true }))
    await box.setValue(true)
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(applications.update).toHaveBeenCalledWith('a1', { assignment_required: true })
    expect(w.text()).toContain('Saved.')
  })

  it('is read-only on built-in apps and for readers', async () => {
    let w = await mountForm(fakeApp({ builtin: true }), ['GlobalAdmin'])
    expect(w.find('#as-required').attributes('disabled')).toBeDefined()
    expect(w.find('button[type=submit]').exists()).toBe(false)

    w = await mountForm(fakeApp({ assignment_required: true }), ['UserAdmin'])
    const box = w.find<HTMLInputElement>('#as-required')
    expect(box.element.checked).toBe(true)
    expect(box.attributes('disabled')).toBeDefined()
  })
})
