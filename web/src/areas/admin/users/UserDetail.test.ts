import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { ApiError } from '@/api/client'
import type { AdminUserDetail, DirectoryRole } from '@/api/types'
import { fakeMe, fakePasskey } from '@/test/helpers'

const users = {
  get: vi.fn(),
  resetMfa: vi.fn(),
  passkeys: vi.fn(),
  sessions: vi.fn(),
  unlinkIdentity: vi.fn(),
}
const directoryRoles = { list: vi.fn() }
vi.mock('@/api/directory', () => ({ users, directoryRoles }))

const { default: UserDetailPage } = await import('./UserDetail.vue')
const { useAuthStore } = await import('@/stores/auth')

const passkeyOnly: AdminUserDetail = {
  ...fakeMe({ id: 'u1', email: 'bob@example.com', has_password: false }),
  mfa: { totp: false, totp_pending: false, recovery_codes_remaining: 0, passkeys: 1, telegram: false },
  identities: [],
}

async function mountPage(roles: DirectoryRole[] = ['UserAdmin']) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ directory_roles: roles }))
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/admin/users', name: 'admin-users', component: UserDetailPage },
      { path: '/admin/users/:id', component: UserDetailPage },
    ],
  })
  await router.push('/admin/users/u1')
  const w = mount(UserDetailPage, { global: { plugins: [pinia, router] }, attachTo: document.body })
  await flushPromises()
  return w
}

const button = (w: ReturnType<typeof mount>, text: string) =>
  w.findAll('button').filter((b) => b.text() === text)

beforeEach(() => {
  document.body.innerHTML = ''
  Object.values(users).forEach((f) => f.mockReset())
  users.get.mockResolvedValue(passkeyOnly)
  users.passkeys.mockResolvedValue({ items: [fakePasskey()] })
  users.sessions.mockResolvedValue({ items: [] })
  directoryRoles.list.mockResolvedValue({ items: [], next_cursor: null })
})

describe('UserDetail passkeys', () => {
  it('treats a passkey-only user as signed up: no invitation to resend', async () => {
    const w = await mountPage()
    expect(w.text()).toContain('Passkey only')
    expect(w.text()).not.toContain('No password yet')
    expect(button(w, 'Resend invitation')).toHaveLength(0)
  })

  it('offers to resend the invitation to a user with neither password nor passkey', async () => {
    users.get.mockResolvedValue({ ...passkeyOnly, mfa: { ...passkeyOnly.mfa, passkeys: 0 } })
    const w = await mountPage()
    expect(w.text()).toContain('No password yet')
    expect(button(w, 'Resend invitation')).toHaveLength(1)
  })

  it('shows the passkeys card and counts passkeys as MFA to reset', async () => {
    const w = await mountPage()
    expect(w.text()).toContain('Passkeys: 1')
    expect(users.passkeys).toHaveBeenCalledWith('u1')
    expect(button(w, 'Reset MFA')[0]?.attributes('disabled')).toBeUndefined()
  })

  it('explains why MFA cannot be reset for a passkey-only user', async () => {
    users.resetMfa.mockRejectedValue(new ApiError(409, { error: 'conflict' }))
    const w = await mountPage()
    await button(w, 'Reset MFA')[0]?.trigger('click')
    expect(w.text()).toContain('recovery codes and passkeys are removed')
    await button(w, 'Reset MFA')[1]?.trigger('click')
    await flushPromises()
    expect(w.find('[role=alert]').text()).toMatch(/Set a password first \(reset password\)/)
  })
})

describe('UserDetail Telegram', () => {
  const telegramOnly: AdminUserDetail = {
    ...passkeyOnly,
    has_password: true,
    mfa: { ...passkeyOnly.mfa, passkeys: 0, telegram: true },
  }

  it('shows a linked Telegram and lets MFA reset unlink it', async () => {
    users.get.mockResolvedValue(telegramOnly)
    users.passkeys.mockResolvedValue({ items: [] })
    const w = await mountPage()
    expect(w.text()).toContain('Telegram linked')
    expect(button(w, 'Reset MFA')[0]?.attributes('disabled')).toBeUndefined()
    await button(w, 'Reset MFA')[0]?.trigger('click')
    expect(w.text()).toContain('Telegram is unlinked')
  })

  it('says nothing about Telegram while none is linked', async () => {
    const w = await mountPage()
    expect(w.text()).not.toContain('Telegram linked')
  })
})

describe('UserDetail linked identities', () => {
  const linked: AdminUserDetail = {
    ...passkeyOnly,
    identities: [
      {
        id: 'li1',
        idp_id: 'idp1',
        idp_name: 'Entra',
        subject: 'sub-123',
        email: 'bob@contoso.com',
        linked_at: '2026-10-01T10:00:00Z',
        last_used_at: null,
      },
    ],
  }

  it('lists them read-only without user write access', async () => {
    users.get.mockResolvedValue(linked)
    const w = await mountPage([])
    expect(w.findAll('h2').map((h) => h.text())).toContain('Linked identities')
    expect(w.text()).toContain('bob@contoso.com')
    expect(w.text()).toContain('sub-123')
    expect(button(w, 'Unlink')).toHaveLength(0)
  })

  it('unlinks after confirmation and reloads the user', async () => {
    users.get.mockResolvedValueOnce(linked).mockResolvedValue(passkeyOnly)
    users.unlinkIdentity.mockResolvedValue(undefined)
    const w = await mountPage()
    await button(w, 'Unlink')[0]?.trigger('click')
    await button(w, 'Unlink')[1]?.trigger('click')
    await flushPromises()
    expect(users.unlinkIdentity).toHaveBeenCalledWith('u1', 'li1')
    expect(users.get).toHaveBeenCalledTimes(2)
    expect(w.text()).toContain('No linked identities.')
  })

  it("shows the server's 409 when it is the last sign-in method", async () => {
    users.get.mockResolvedValue(linked)
    users.unlinkIdentity.mockRejectedValue(
      new ApiError(409, { error: 'conflict', error_description: 'last sign-in method' }),
    )
    const w = await mountPage()
    await button(w, 'Unlink')[0]?.trigger('click')
    await button(w, 'Unlink')[1]?.trigger('click')
    await flushPromises()
    expect(w.find('[role=alert]').text()).toBe('last sign-in method')
  })
})
