import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia, type Pinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { h, type Component } from 'vue'
import { adminPageKey } from '@/router/admin'
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

/** Like `AdminLayout`'s outlet: the routed page keyed by `adminPageKey`. */
const KeyedView = {
  render: () =>
    h(RouterView, null, {
      default: ({ Component: page, route }: { Component: Component; route: Parameters<typeof adminPageKey>[0] }) =>
        h(page, { key: adminPageKey(route) }),
    }),
}

/** Mounts `component` itself, or with `keyed` the outlet that routes to it. */
async function mountAt(path: string, component: object, keyed = false) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/admin/tenants', name: 'admin-tenants', component },
      { path: '/admin/tenants/:slug/users', name: 'admin-tenant-users', component },
    ],
  })
  await router.push(path)
  const w = mount(keyed ? KeyedView : component, { global: { plugins: [pinia, router] }, attachTo: document.body })
  await flushPromises()
  return Object.assign(w, { router })
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

  it('follows the slug when the route is reused for another tenant', async () => {
    await signIn()
    const carol: User = { ...bob, id: 'u2', email: 'carol@fabrikam.example' }
    const calls = mockFetch(page([bob]), page([bob]), { body: bobDetail }, page([carol]))
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage, true)
    await w.find('input[type=search]').setValue('bob')
    await new Promise((r) => setTimeout(r, SEARCH_DEBOUNCE_MS + 50))
    await flushPromises()
    await buttons(w, 'bob@contoso.example')[0]?.trigger('click')
    await flushPromises()
    expect(w.text()).toContain('Recovery codes left')
    expect(w.find('tr[aria-current=true]').text()).toContain('bob@contoso.example')
    await w.router.push('/admin/tenants/fabrikam/users')
    await flushPromises()
    await new Promise((r) => setTimeout(r, SEARCH_DEBOUNCE_MS + 50))
    await flushPromises()
    expect(calls.map((c) => c.url)).toEqual([
      '/api/v1/tenants/contoso/users?limit=25',
      '/api/v1/tenants/contoso/users?limit=25&search=bob',
      '/api/v1/tenants/contoso/users/u1',
      '/api/v1/tenants/fabrikam/users?limit=25',
    ])
    expect((w.find('input[type=search]').element as HTMLInputElement).value).toBe('')
    expect(w.text()).toContain('Users of fabrikam')
    expect(w.text()).toContain('carol@fabrikam.example')
    expect(w.text()).not.toContain('bob@contoso.example')
    expect(w.text()).not.toContain('Recovery codes left')
    expect(w.find('tr[aria-current]').exists()).toBe(false)
  })

  it('never fetches for an "undefined" tenant when navigating away', async () => {
    await signIn()
    const calls = mockFetch(page([bob]), page([]))
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage)
    await w.router.push('/admin/tenants')
    await flushPromises()
    expect(calls.map((c) => c.url)).toEqual(['/api/v1/tenants/contoso/users?limit=25'])
    expect(w.text()).toContain('Users of contoso')
  })

  const wait = async () => {
    await new Promise((r) => setTimeout(r, SEARCH_DEBOUNCE_MS + 50))
    await flushPromises()
  }

  const heading = (w: ReturnType<typeof mount>) => w.find('section[aria-label="Selected user"] h2')

  it('keeps the panel through a page, a search and a failed load that no longer list the user', async () => {
    await signIn()
    const carol: User = { ...bob, id: 'u2', email: 'carol@contoso.example' }
    const calls = mockFetch(
      { body: { items: [bob], next_cursor: 'c2' } },
      { body: bobDetail },
      page([carol]),
      page([]),
      { status: 500, body: { error: 'server_error' } },
    )
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage)
    await buttons(w, 'bob@contoso.example')[0]?.trigger('click')
    await flushPromises()
    expect(heading(w).text()).toBe('bob@contoso.example')
    await buttons(w, 'Next')[0]?.trigger('click')
    await flushPromises()
    expect(w.text()).toContain('carol@contoso.example')
    expect(heading(w).text()).toBe('bob@contoso.example')
    expect(w.find('tr[aria-current]').exists()).toBe(false)
    await w.find('input[type=search]').setValue('zzz')
    await wait()
    expect(w.text()).toContain('No users found.')
    expect(heading(w).text()).toBe('bob@contoso.example')
    await w.findComponent({ name: 'ListShell' }).props('list').load()
    await flushPromises()
    expect(heading(w).text()).toBe('bob@contoso.example')
    expect(buttons(w, 'Reset password')).toHaveLength(1)
    expect(calls.map((c) => c.url)).toEqual([
      '/api/v1/tenants/contoso/users?limit=25',
      '/api/v1/tenants/contoso/users/u1',
      '/api/v1/tenants/contoso/users?limit=25&cursor=c2',
      '/api/v1/tenants/contoso/users?limit=25&search=zzz',
      '/api/v1/tenants/contoso/users?limit=25&search=zzz',
    ])
  })

  it('keeps the shown password when a stale search response lands mid-dialog', async () => {
    await signIn()
    const carol: User = { ...bob, id: 'u2', email: 'carol@contoso.example' }
    const calls = mockFetch(
      page([bob]),
      { body: bobDetail },
      { body: { one_time_password: 'Temp-123', must_change_password: true } },
      { body: { ...bobDetail, has_password: true } },
    )
    let release: (r: Response) => void = () => {}
    const real = globalThis.fetch
    vi.stubGlobal('fetch', (url: string, init?: RequestInit) => {
      if (!url.includes('search=')) return real(url, init)
      calls.push({ url, method: 'GET', headers: {}, body: undefined })
      return new Promise<Response>((r) => (release = r))
    })
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage)
    await buttons(w, 'bob@contoso.example')[0]?.trigger('click')
    await flushPromises()
    await w.find('input[type=search]').setValue('carol')
    await wait()
    await buttons(w, 'Reset password')[0]?.trigger('click')
    await buttons(w, 'Reset password')[1]?.trigger('click')
    await flushPromises()
    expect(w.find('[data-testid=secret-values]').text()).toBe('Temp-123')
    release(new Response(JSON.stringify(page([carol]).body), { headers: { 'content-type': 'application/json' } }))
    await flushPromises()
    expect(w.text()).toContain('carol@contoso.example')
    expect(w.find('[data-testid=secret-values]').text()).toBe('Temp-123')
    expect(heading(w).text()).toBe('bob@contoso.example')
    expect(calls.map((c) => c.url)).toEqual([
      '/api/v1/tenants/contoso/users?limit=25',
      '/api/v1/tenants/contoso/users/u1',
      '/api/v1/tenants/contoso/users?limit=25&search=carol',
      '/api/v1/tenants/contoso/users/u1/reset-password',
      '/api/v1/tenants/contoso/users/u1',
    ])
  })

  it('Close clears the selection', async () => {
    await signIn()
    mockFetch(page([bob]), { body: bobDetail })
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage)
    await buttons(w, 'bob@contoso.example')[0]?.trigger('click')
    await flushPromises()
    expect(w.find('tr[aria-current=true]').exists()).toBe(true)
    await buttons(w, 'Close')[0]?.trigger('click')
    await flushPromises()
    expect(w.find('section[aria-label="Selected user"]').exists()).toBe(false)
    expect(w.find('tr[aria-current]').exists()).toBe(false)
  })

  it('switches the panel when another row is clicked', async () => {
    await signIn()
    const carol: User = { ...bob, id: 'u2', email: 'carol@contoso.example', display_name: 'Carol' }
    const calls = mockFetch(page([bob, carol]), { body: bobDetail }, { body: { ...bobDetail, ...carol } })
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage)
    await buttons(w, 'bob@contoso.example')[0]?.trigger('click')
    await flushPromises()
    expect(heading(w).text()).toBe('bob@contoso.example')
    await buttons(w, 'carol@contoso.example')[0]?.trigger('click')
    await flushPromises()
    expect(heading(w).text()).toBe('carol@contoso.example')
    expect(w.find('section[aria-label="Selected user"]').text()).toContain('Carol')
    expect(w.find('tr[aria-current=true]').text()).toContain('carol@contoso.example')
    expect(calls.at(-1)?.url).toBe('/api/v1/tenants/contoso/users/u2')
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
    expect(post?.body).toBeUndefined()
    expect(w.find('[data-testid=secret-values]').text()).toBe('Temp-123')
    await buttons(w, 'Done')[0]?.trigger('click')
    await flushPromises()
    expect(w.find('[data-testid=secret-values]').exists()).toBe(false)
    expect(w.html()).not.toContain('Temp-123')
    expect(calls.at(-1)?.url).toBe('/api/v1/tenants/contoso/users?limit=25')
  })

  it('refreshes the list only once the password is closed, and a failed refresh keeps the panel', async () => {
    await signIn()
    const calls = mockFetch(
      page([bob]),
      { body: bobDetail },
      { body: { one_time_password: 'Temp-123', must_change_password: true } },
      { body: { ...bobDetail, has_password: true } },
      { status: 500, body: { error: 'server_error' } },
    )
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage)
    await buttons(w, 'bob@contoso.example')[0]?.trigger('click')
    await flushPromises()
    await buttons(w, 'Reset password')[0]?.trigger('click')
    await buttons(w, 'Reset password')[1]?.trigger('click')
    await flushPromises()
    expect(w.find('[data-testid=secret-values]').text()).toBe('Temp-123')
    expect(calls.map((c) => c.url)).toEqual([
      '/api/v1/tenants/contoso/users?limit=25',
      '/api/v1/tenants/contoso/users/u1',
      '/api/v1/tenants/contoso/users/u1/reset-password',
      '/api/v1/tenants/contoso/users/u1',
    ])
    await buttons(w, 'Done')[0]?.trigger('click')
    await flushPromises()
    expect(calls.at(-1)?.url).toBe('/api/v1/tenants/contoso/users?limit=25')
    expect(calls).toHaveLength(5)
    expect(w.text()).toContain('Recovery codes left')
    expect(w.html()).not.toContain('Temp-123')
  })

  it('keeps the shown password when the list refresh fails mid-dialog', async () => {
    await signIn()
    mockFetch(
      page([bob]),
      { body: bobDetail },
      { body: { one_time_password: 'Temp-123', must_change_password: true } },
      { body: { ...bobDetail, has_password: true } },
      { status: 500, body: { error: 'server_error' } },
    )
    const w = await mountAt('/admin/tenants/contoso/users', TenantUsersPage)
    await buttons(w, 'bob@contoso.example')[0]?.trigger('click')
    await flushPromises()
    await buttons(w, 'Reset password')[0]?.trigger('click')
    await buttons(w, 'Reset password')[1]?.trigger('click')
    await flushPromises()
    // Stand-in for any list load landing while the dialog is open.
    await w.findComponent({ name: 'ListShell' }).props('list').load()
    await flushPromises()
    expect(w.find('[data-testid=secret-values]').text()).toBe('Temp-123')
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
