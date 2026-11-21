import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { Application, DirectoryRole } from '@/api/types'
import { fakeMe } from '@/test/helpers'

const applications = { get: vi.fn(), update: vi.fn() }
vi.mock('@/api/applications', () => ({ applications }))

const { default: AppAuthentication } = await import('./AppAuthentication.vue')
const { useAuthStore } = await import('@/stores/auth')
const { useApplicationStore } = await import('@/stores/application')

function fakeApp(over: Partial<Application> = {}): Application {
  return {
    id: 'a1',
    client_id: 'shop',
    display_name: 'Shop',
    client_type: 'public',
    builtin: false,
    redirect_uris: ['https://shop.example/cb'],
    post_logout_redirect_uris: [],
    web_origins: ['https://other.example'],
    effective_web_origins: ['https://other.example', 'https://shop.example'],
    identifier_uri: null,
    audience: 'api://shop',
    access_token_format: 'jwt',
    signing_alg: 'RS256',
    groups_claim_format: 'id',
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
  const w = mount(AppAuthentication, { global: { plugins: [pinia] } })
  await flushPromises()
  return w
}

beforeEach(() => {
  Object.values(applications).forEach((f) => f.mockReset())
})

describe('AppAuthentication', () => {
  it('edits explicit origins and shows the ones derived from redirect URIs', async () => {
    const w = await mountForm(fakeApp())
    const origins = w.find('#aa-origins')
    expect((origins.element as HTMLTextAreaElement).value).toBe('https://other.example')
    expect(w.find('[data-testid=derived-origins]').text()).toContain('https://shop.example')

    applications.update.mockResolvedValue(fakeApp({ web_origins: ['https://a.example'] }))
    await origins.setValue(' https://a.example \n\n')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(applications.update).toHaveBeenCalledWith('a1', { web_origins: ['https://a.example'] })
    expect(w.text()).toContain('Saved.')
  })

  it('shows no derived origins when all are explicit, and is read-only for built-ins', async () => {
    const w = await mountForm(
      fakeApp({ builtin: true, web_origins: [], effective_web_origins: [] }),
      ['GlobalAdmin'],
    )
    expect(w.find('[data-testid=derived-origins]').exists()).toBe(false)
    expect(w.find('#aa-origins').attributes('disabled')).toBeDefined()
    expect(w.find('button[type=submit]').exists()).toBe(false)
  })
})
