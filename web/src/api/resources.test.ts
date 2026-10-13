import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { FakeManager, fakeUser, mockFetch } from '@/test/helpers'

vi.mock('@/auth/oidc', () => ({
  createUserManager: (t: string, a: string) => {
    const m = new FakeManager(t, a)
    m.stored = fakeUser({ access_token: 'tok' })
    return m
  },
}))

const { useAuthStore } = await import('@/stores/auth')
const { users, groups, directoryRoles } = await import('./directory')
const { applications, secrets, scopes, appRoles, requiredPermissions } = await import(
  './applications'
)
const { roleAssignments, consents, auditEvents, settings, tenants } = await import('./access')
const { me } = await import('./me')

const T = '/api/v1/tenants/con%20toso'

beforeEach(async () => {
  setActivePinia(createPinia())
  await useAuthStore().ensureSignedIn('con toso', 'admin', '/')
})
afterEach(() => vi.unstubAllGlobals())

describe('directory resources', () => {
  it('lists users with paging and search, returning next_cursor', async () => {
    const page = { items: [{ id: 'u1' }], next_cursor: 'c2' }
    const calls = mockFetch({ body: page })
    const res = await users.list({ limit: 25, cursor: 'c1', search: 'ann b' })
    expect(res).toEqual(page)
    expect(calls[0]?.url).toBe(`${T}/users?limit=25&cursor=c1&search=ann+b`)
    expect(calls[0]?.headers.Authorization).toBe('Bearer tok')
  })

  it('omits empty paging parameters', async () => {
    const calls = mockFetch({ body: { items: [], next_cursor: null } })
    await users.list({ cursor: null, search: '' })
    expect(calls[0]?.url).toBe(`${T}/users`)
  })

  it('creates a user and returns the one-time password', async () => {
    const calls = mockFetch({ status: 201, body: { user: { id: 'u' }, one_time_password: 'otp' } })
    const res = await users.create({ email: 'a@b.c', display_name: 'A' })
    expect(res.one_time_password).toBe('otp')
    expect(calls[0]).toMatchObject({
      method: 'POST',
      url: `${T}/users`,
      body: { email: 'a@b.c', display_name: 'A' },
    })
  })

  it('escapes ids and sends {} for a generated password reset', async () => {
    const calls = mockFetch({ body: { one_time_password: 'x', must_change_password: true } })
    await users.resetPassword('a/b')
    expect(calls[0]).toMatchObject({ url: `${T}/users/a%2Fb/reset-password`, body: {} })
  })

  it('manages group members', async () => {
    const calls = mockFetch({ status: 204 }, { body: { items: [], next_cursor: null } }, {})
    await groups.addMember('g1', 'u1')
    await groups.members('g1', { limit: 10 })
    await groups.removeMember('g1', 'u1')
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      `POST ${T}/groups/g1/members`,
      `GET ${T}/groups/g1/members?limit=10`,
      `DELETE ${T}/groups/g1/members/u1`,
    ])
    expect(calls[0]?.body).toEqual({ user_id: 'u1' })
  })

  it('filters and assigns directory roles', async () => {
    const calls = mockFetch({ body: { items: [], next_cursor: null } }, { status: 201, body: {} })
    await directoryRoles.list({ user_id: 'u1', role: 'GlobalAdmin' })
    await directoryRoles.assign('u1', 'UserAdmin')
    expect(calls[0]?.url).toBe(`${T}/directory-roles?user_id=u1&role=GlobalAdmin`)
    expect(calls[1]?.body).toEqual({ user_id: 'u1', role: 'UserAdmin' })
  })
})

describe('application resources', () => {
  it('patches an application', async () => {
    const calls = mockFetch({ body: { id: 'a1' } })
    await applications.update('a1', { identifier_uri: null })
    expect(calls[0]).toMatchObject({
      method: 'PATCH',
      url: `${T}/applications/a1`,
      body: { identifier_uri: null },
    })
  })

  it('returns the secret value only from create', async () => {
    const calls = mockFetch({ status: 201, body: { id: 's1', hint: 'abc', secret: 'VALUE' } })
    const s = await secrets.create('a1', { expires_in_days: 90 })
    expect(s.secret).toBe('VALUE')
    expect(calls[0]?.url).toBe(`${T}/applications/a1/secrets`)
  })

  it('addresses scopes, roles and required permissions under the app', async () => {
    const calls = mockFetch({}, {}, {}, {})
    await scopes.update('a1', 's1', { admin_consent_required: true })
    await appRoles.remove('a1', 'r1')
    await requiredPermissions.create('a1', {
      resource_application_id: 'api',
      type: 'delegated',
      value: 'Orders.Read',
    })
    await requiredPermissions.remove('a1', 'p1')
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      `PATCH ${T}/applications/a1/scopes/s1`,
      `DELETE ${T}/applications/a1/roles/r1`,
      `POST ${T}/applications/a1/required-permissions`,
      `DELETE ${T}/applications/a1/required-permissions/p1`,
    ])
  })
})

describe('access resources', () => {
  it('grants admin consent for everything required by default', async () => {
    const calls = mockFetch({ body: { grant: null, role_assignments: [] } })
    await consents.grant({ client_application_id: 'c', resource_application_id: 'r' })
    expect(calls[0]).toMatchObject({
      url: `${T}/consents`,
      body: { client_application_id: 'c', resource_application_id: 'r' },
    })
  })

  it('filters role assignments and the audit log', async () => {
    const empty = { body: { items: [], next_cursor: null } }
    const calls = mockFetch(empty, empty)
    await roleAssignments.list({ resource_application_id: 'api' })
    await auditEvents.list({ event_type: 'user.create', from: '2026-01-01T00:00:00.000Z' })
    expect(calls[0]?.url).toBe(`${T}/role-assignments?resource_application_id=api`)
    expect(calls[1]?.url).toBe(
      `${T}/audit-events?event_type=user.create&from=2026-01-01T00%3A00%3A00.000Z`,
    )
  })

  it('uses tenant settings and the system tenants endpoints', async () => {
    const calls = mockFetch({}, {}, {})
    await settings.update({ audit_retention_days: 60 })
    await tenants.list({ search: 'con' })
    await tenants.update('fab rikam', { disabled: true })
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      `PATCH ${T}/settings`,
      'GET /api/v1/tenants?search=con',
      'PATCH /api/v1/tenants/fab%20rikam',
    ])
  })
})

describe('me', () => {
  it('sends the password in the body when removing TOTP', async () => {
    const calls = mockFetch({ status: 204 })
    await me.removeTotp('pw')
    expect(calls[0]).toMatchObject({ method: 'DELETE', url: `${T}/me/totp`, body: { password: 'pw' } })
  })

  it('maps change-password fields', async () => {
    const calls = mockFetch({ status: 204 })
    await me.changePassword('old', 'new-password-123')
    expect(calls[0]?.body).toEqual({ current_password: 'old', new_password: 'new-password-123' })
  })
})
