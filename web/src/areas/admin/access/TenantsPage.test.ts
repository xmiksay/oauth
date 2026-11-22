import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia, type Pinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import type { Tenant } from '@/api/types'
import { FakeManager, fakeMe, fakeUser, mockFetch } from '@/test/helpers'

vi.mock('@/auth/oidc', () => ({
  createUserManager: (a: string) => {
    const m = new FakeManager(a)
    m.stored = fakeUser({ access_token: 'tok' })
    return m
  },
}))

const { default: TenantsPage } = await import('./TenantsPage.vue')
const { useAuthStore } = await import('@/stores/auth')
const { useTenantStore } = await import('@/stores/tenant')

const page = (items: unknown[]) => ({ body: { items, next_cursor: null } })
const tenant = (over: Partial<Tenant>): Tenant => ({
  id: 't1',
  slug: 'contoso',
  origin: 'https://contoso.id.example.com',
  display_name: 'Contoso',
  is_system: false,
  disabled: false,
  audit_retention_days: 90,
  mfa_policy: 'optional',
  logout_revokes_refresh_tokens: true,
  allow_non_expiring_secrets: false,
  created_at: '',
  updated_at: '',
  ...over,
})

let pinia: Pinia

async function mountPage() {
  pinia = createPinia()
  setActivePinia(pinia)
  useTenantStore().slug = 'system'
  const auth = useAuthStore()
  await auth.ensureSignedIn('admin', '/')
  auth.setMe(fakeMe({ directory_roles: ['GlobalAdmin'], tenant_is_system: true }))
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/admin/tenants', name: 'admin-tenants', component: TenantsPage },
      { path: '/admin/tenants/:slug/users', name: 'admin-tenant-users', component: TenantsPage },
    ],
  })
  await router.push('/admin/tenants')
  const w = mount(TenantsPage, { global: { plugins: [pinia, router] }, attachTo: document.body })
  await flushPromises()
  return w
}

beforeEach(() => {
  document.body.innerHTML = ''
})
afterEach(() => vi.unstubAllGlobals())

describe('TenantsPage', () => {
  it('links every tenant but the system tenant to its users', async () => {
    mockFetch(
      page([
        tenant({ id: 't0', slug: 'system', display_name: 'System', is_system: true }),
        tenant({ disabled: true }),
      ]),
    )
    const w = await mountPage()
    const links = w.findAll('a').filter((a) => a.text() === 'Users')
    expect(links).toHaveLength(1)
    expect(links[0]?.attributes('href')).toBe('/admin/tenants/contoso/users')
  })

  it("shows each tenant's origin from the server (the apex for APEX_TENANT)", async () => {
    mockFetch(
      page([
        tenant({ id: 't2', slug: 'prod', origin: 'https://id.example.com' }),
        tenant({}),
      ]),
    )
    const w = await mountPage()
    expect(w.text()).toContain('https://id.example.com')
    expect(w.text()).not.toContain('https://prod.')
    expect(w.text()).toContain('https://contoso.id.example.com')
  })

  it("tells the new admin to sign in at the server's origin for the tenant", async () => {
    const created = tenant({ id: 't3', slug: 'prod', origin: 'https://id.example.com' })
    const calls = mockFetch(
      page([]),
      {
        status: 201,
        body: { tenant: created, admin: { email: 'ann@prod.test' }, one_time_password: 'OTP' },
      },
      page([created]),
    )
    const w = await mountPage()
    await w.findAll('button').find((b) => b.text() === 'New tenant')?.trigger('click')
    await w.find('#nt-slug').setValue('prod')
    await w.find('#nt-name').setValue('Prod')
    await w.find('#nt-email').setValue('ann@prod.test')
    await w.find('form#create-tenant').trigger('submit')
    await flushPromises()
    expect(calls[1]?.method).toBe('POST')
    const dialog = w.findComponent({ name: 'SecretOnceDialog' })
    expect(dialog.props('values')).toEqual(['OTP'])
    expect(dialog.props('description')).toBe('ann@prod.test — sign in at https://id.example.com/admin')
  })
})
