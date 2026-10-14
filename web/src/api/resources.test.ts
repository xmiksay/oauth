import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import {
  ASSERTION_JSON,
  CREATION_OPTIONS,
  FakeManager,
  REGISTRATION_JSON,
  REQUEST_OPTIONS,
  fakeUser,
  mockFetch,
} from '@/test/helpers'

vi.mock('@/auth/oidc', () => ({
  createUserManager: (a: string) => {
    const m = new FakeManager(a)
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

// The tenant is the host: no tenant segment in API paths.
const T = '/api/v1'

beforeEach(async () => {
  setActivePinia(createPinia())
  await useAuthStore().ensureSignedIn('admin', '/')
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
    await me.removeTotp({ password: 'pw' })
    expect(calls[0]).toMatchObject({ method: 'DELETE', url: `${T}/me/totp`, body: { password: 'pw' } })
  })

  it('maps change-password fields', async () => {
    const calls = mockFetch({ status: 204 }, { status: 204 })
    await me.changePassword('new-password-123', { password: 'old' })
    await me.changePassword('new-password-123', { passkey: ASSERTION_JSON })
    expect(calls[0]?.body).toEqual({ current_password: 'old', new_password: 'new-password-123' })
    expect(calls[1]?.body).toEqual({ passkey: ASSERTION_JSON, new_password: 'new-password-123' })
  })

  it('maps the email change and PUTs notification preferences', async () => {
    const settings = { channels: { email: true, telegram: false }, items: [] }
    const calls = mockFetch({ status: 202, body: { sent: true } }, { body: settings })
    await me.changeEmail('new@b.c', { password: 'pw' })
    const items = [{ event: 'new_sign_in' as const, email: false, telegram: false }]
    expect(await me.updateNotifications(items)).toEqual(settings)
    expect(calls[0]).toMatchObject({
      method: 'POST',
      url: `${T}/me/email`,
      body: { new_email: 'new@b.c', password: 'pw' },
    })
    expect(calls[1]).toMatchObject({ method: 'PUT', url: `${T}/me/notifications`, body: { items } })
  })

  it('invites a user and re-sends the invitation with {}', async () => {
    const calls = mockFetch({ status: 201, body: { user: { id: 'u' }, invite_sent: true } }, {})
    await users.create({ email: 'a@b.c', display_name: 'A', invite: true })
    await users.resendInvite('u/1')
    expect(calls[0]?.body).toEqual({ email: 'a@b.c', display_name: 'A', invite: true })
    expect(calls[1]).toMatchObject({ method: 'POST', url: `${T}/users/u%2F1/invite`, body: {} })
  })
})

describe('passkeys', () => {
  it('re-authenticates with a passkey and registers, renames and removes passkeys', async () => {
    const pk = { id: 'p/1', name: 'Laptop' }
    const calls = mockFetch(
      { body: REQUEST_OPTIONS },
      { body: CREATION_OPTIONS },
      { status: 201, body: pk },
      { status: 201, body: pk },
      { body: pk },
      { status: 204 },
      { body: { recovery_codes: [] } },
    )
    const reauth = { passkey: ASSERTION_JSON }
    expect(await me.reauthOptions()).toEqual(REQUEST_OPTIONS)
    expect(await me.passkeyOptions(reauth)).toEqual(CREATION_OPTIONS)
    await me.addPasskey(REGISTRATION_JSON, 'Laptop')
    await me.addPasskey(REGISTRATION_JSON)
    await me.renamePasskey('p/1', 'Work')
    await me.removePasskey('p/1', { password: 'pw' })
    await me.regenerateRecoveryCodes(reauth)
    expect(calls.map((c) => [c.method, c.url, c.body])).toEqual([
      ['POST', `${T}/me/reauth/options`, {}],
      ['POST', `${T}/me/passkeys/options`, reauth],
      ['POST', `${T}/me/passkeys`, { credential: REGISTRATION_JSON, name: 'Laptop' }],
      ['POST', `${T}/me/passkeys`, { credential: REGISTRATION_JSON }],
      ['PATCH', `${T}/me/passkeys/p%2F1`, { name: 'Work' }],
      ['DELETE', `${T}/me/passkeys/p%2F1`, { password: 'pw' }],
      ['POST', `${T}/me/recovery-codes`, reauth],
    ])
  })

  it("lists and removes a user's passkeys as an admin", async () => {
    const calls = mockFetch({ body: { items: [] } }, { status: 204 })
    await users.passkeys('u/1')
    await users.removePasskey('u/1', 'p/1')
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      `GET ${T}/users/u%2F1/passkeys`,
      `DELETE ${T}/users/u%2F1/passkeys/p%2F1`,
    ])
  })
})
