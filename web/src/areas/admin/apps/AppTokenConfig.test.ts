import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { Application, DirectoryRole } from '@/api/types'
import { fakeMe } from '@/test/helpers'

const applications = { get: vi.fn(), update: vi.fn() }
vi.mock('@/api/applications', () => ({ applications }))

const { default: AppTokenConfig } = await import('./AppTokenConfig.vue')
const { useAuthStore } = await import('@/stores/auth')
const { useApplicationStore } = await import('@/stores/application')

function fakeApp(over: Partial<Application> = {}): Application {
  return {
    id: 'a1',
    client_id: 'k8s',
    display_name: 'Kubernetes',
    client_type: 'confidential',
    builtin: false,
    redirect_uris: [],
    post_logout_redirect_uris: [],
    web_origins: [],
    effective_web_origins: [],
    identifier_uri: 'api://k8s',
    audience: 'api://k8s',
    access_token_format: 'jwt',
    signing_alg: 'RS256',
    groups_claim_format: 'id',
    assignment_required: false,
    access_token_ttl_secs: 3600,
    refresh_token_ttl_secs: 86400,
    device_code_enabled: false,
    mfa_policy: 'inherit',
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
  const w = mount(AppTokenConfig, { global: { plugins: [pinia] } })
  await flushPromises()
  return w
}

beforeEach(() => {
  Object.values(applications).forEach((f) => f.mockReset())
})

describe('AppTokenConfig', () => {
  it('switches the groups claim to names, sending only that change', async () => {
    const w = await mountForm(fakeApp())
    const select = w.find('#tc-groups')
    expect((select.element as HTMLSelectElement).value).toBe('id')

    applications.update.mockResolvedValue(fakeApp({ groups_claim_format: 'name' }))
    await select.setValue('name')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(applications.update).toHaveBeenCalledWith('a1', { groups_claim_format: 'name' })
    expect(w.text()).toContain('Saved.')
  })

  it('sends no PATCH (so no mfa_policy) for an untouched form', async () => {
    const w = await mountForm(fakeApp({ mfa_policy: 'required' }))
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(applications.update).not.toHaveBeenCalled()
  })

  it('shows the current format and locks it on built-in apps', async () => {
    const w = await mountForm(fakeApp({ builtin: true, groups_claim_format: 'name' }), [
      'GlobalAdmin',
    ])
    const select = w.find('#tc-groups')
    expect((select.element as HTMLSelectElement).value).toBe('name')
    expect(select.attributes('disabled')).toBeDefined()
  })

  it('lets a GlobalAdmin require MFA on a built-in app', async () => {
    const w = await mountForm(fakeApp({ builtin: true }), ['GlobalAdmin'])
    const select = w.find('#tc-mfa')
    expect((select.element as HTMLSelectElement).value).toBe('inherit')
    expect(select.attributes('disabled')).toBeUndefined()

    applications.update.mockResolvedValue(fakeApp({ builtin: true, mfa_policy: 'required' }))
    await select.setValue('required')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(applications.update).toHaveBeenCalledWith('a1', { mfa_policy: 'required' })
  })
})
