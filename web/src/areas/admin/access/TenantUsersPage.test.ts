import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia, type Pinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import type { AdminUserDetail, Tenant, User } from '@/api/types'
import { SEARCH_DEBOUNCE_MS } from '@/composables/usePagedList'
import { FakeManager, fakeMe, fakeUser, mockFetch } from '@/test/helpers'

vi.mock('@/auth/oidc', () => ({
  createUserManager: (a: string) => {
    const m = new FakeManager(a)
    m.stored = fakeUser({ access_token: 'tok' })
    return m
  },
}))

const { default: TenantUsersPage } = await import('./TenantUsersPage.vue')
const { default: TenantsPage } = await import('./TenantsPage.vue')
const { useAuthStore } = await import('@/stores/auth')
const { useTenantStore } = await import('@/stores/tenant')

const bob: User = {
  id: 'u1',
  email: 'bob@contoso.example',
  display_name: 'Bob',
  user_type: 'member',
  email_verified: true,
  disabled: false,
  must_change_password: false,
  has_password: false,
  created_at: '',
  updated_at: '',
}
const bobDetail: AdminUserDetail = {
  ...bob,
  directory_roles: ['GlobalAdmin'],
  mfa: { totp: false, totp_pending: false, recovery_codes_remaining: 0, passkeys: 1, telegram: false },
  identities: [],
}
const page = (items: unknown[]) => ({ body: { items, next_cursor: null } })

let pinia: Pinia

async function signIn(roles: AdminUserDetail['directory_roles'] = ['GlobalAdmin']) {
  pinia = createPinia()
  setActivePinia(pinia)
  useTenantStore().slug = 'system'
  const auth = useAuthStore()
  await auth.ensureSignedIn('admin', '/')
  auth.setMe(fakeMe({ directory_roles: roles }))
}

async function mountAt(path: string, component: object) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/admin/tenants', name: 'admin-tenants', component },
      { path: '/admin/tenants/:slug/users', name: 'admin-tenant-users', component },
    ],
  })
  await router.push(path)
  const w = mount(component, { global: { plugins: [pinia, router] }, attachTo: document.body })
  await flushPromises()
  return w
}

const buttons = (w: ReturnType<typeof mount>, text: string) =>
  w.findAll('button').filter((b) => b.text() === text)

beforeEach(() => {
  document.body.innerHTML = ''
})
afterEach(() => vi.unstubAllGlobals())

describe('TenantUsersPage', () => {
  it('lists the tenant’s users and searches them', async () => {
    await signIn()
    const calls = mockFetch(page([bob]), page([]))
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage)
    expect(w.text()).toContain('bob@contoso.example')
    expect(w.text()).toContain('No password')
    await w.find('input[type=search]').setValue('bo b')
    await new Promise((r) => setTimeout(r, SEARCH_DEBOUNCE_MS + 50))
    await flushPromises()
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      'GET /api/v1/tenants/contoso/users?limit=25',
      'GET /api/v1/tenants/contoso/users?limit=25&search=bo+b',
    ])
    expect(calls[0]?.headers.Authorization).toBe('Bearer tok')
  })

  it('resets the password and shows it once, cleared on close', async () => {
    await signIn()
    const calls = mockFetch(
      page([bob]),
      { body: bobDetail },
      { body: { one_time_password: 'Temp-123', must_change_password: true } },
      { body: { ...bobDetail, has_password: true } },
      page([bob]),
    )
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage)
    await buttons(w, 'bob@contoso.example')[0]?.trigger('click')
    await flushPromises()
    expect(w.text()).toContain('GlobalAdmin')
    expect(w.text()).toContain('Passkeys: 1')
    await buttons(w, 'Reset password')[0]?.trigger('click')
    expect(w.text()).toContain('shown once')
    await buttons(w, 'Reset password')[1]?.trigger('click')
    await flushPromises()
    const post = calls.find((c) => c.method === 'POST')
    expect(post?.url).toBe('/api/v1/tenants/contoso/users/u1/reset-password')
    expect(post?.body).toEqual({})
    expect(w.find('[data-testid=secret-values]').text()).toBe('Temp-123')
    await buttons(w, 'Done')[0]?.trigger('click')
    await flushPromises()
    expect(w.find('[data-testid=secret-values]').exists()).toBe(false)
    expect(w.html()).not.toContain('Temp-123')
  })

  it('explains the 409 of an MFA reset for a passkey-only user', async () => {
    await signIn()
    const calls = mockFetch(page([bob]), { body: bobDetail }, { status: 409, body: { error: 'conflict' } })
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage)
    await buttons(w, 'bob@contoso.example')[0]?.trigger('click')
    await flushPromises()
    await buttons(w, 'Reset MFA')[0]?.trigger('click')
    await buttons(w, 'Reset MFA')[1]?.trigger('click')
    await flushPromises()
    expect(calls.at(-1)?.url).toBe('/api/v1/tenants/contoso/users/u1/reset-mfa')
    expect(w.find('[role=alert]').text()).toMatch(/Set a password first \(reset password\)/)
  })

  it('disables Reset MFA without factors', async () => {
    await signIn()
    mockFetch(page([bob]), { body: { ...bobDetail, mfa: { ...bobDetail.mfa, passkeys: 0 } } })
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage)
    await buttons(w, 'bob@contoso.example')[0]?.trigger('click')
    await flushPromises()
    expect(buttons(w, 'Reset MFA')[0]?.attributes('disabled')).toBeDefined()
  })

  it('stays empty for anyone but a system Global Admin', async () => {
    await signIn(['UserAdmin'])
    const calls = mockFetch()
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage)
    expect(w.text()).toContain('Only a Global Administrator of the system tenant')
    expect(calls).toHaveLength(0)
  })
})

describe('TenantsPage users link', () => {
  const tenant = (over: Partial<Tenant>): Tenant => ({
    id: 't1',
    slug: 'contoso',
    display_name: 'Contoso',
    is_system: false,
    disabled: false,
    audit_retention_days: 90,
    created_at: '',
    updated_at: '',
    ...over,
  })

  it('links every tenant but the system tenant to its users', async () => {
    await signIn()
    mockFetch(
      page([
        tenant({ id: 't0', slug: 'system', display_name: 'System', is_system: true }),
        tenant({ disabled: true }),
      ]),
    )
    const w = await mountAt('/admin/tenants', TenantsPage)
    const links = w.findAll('a').filter((a) => a.text() === 'Users')
    expect(links).toHaveLength(1)
    expect(links[0]?.attributes('href')).toBe('/admin/tenants/contoso/users')
  })
})
