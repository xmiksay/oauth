import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import type { PageQuery, Paged, User } from '@/api/types'

const list = vi.fn<(q: PageQuery) => Promise<Paged<User>>>()
vi.mock('@/api/directory', () => ({ users: { list: (q: PageQuery) => list(q) } }))

const { default: UsersList } = await import('./UsersList.vue')
const { useAuthStore } = await import('@/stores/auth')

function user(n: number): User {
  return {
    id: `u${n}`,
    email: `user${n}@example.com`,
    display_name: `User ${n}`,
    user_type: 'member',
    email_verified: false,
    disabled: n === 2,
    must_change_password: false,
    has_password: true,
    created_at: '2026-10-13T10:00:00.000Z',
    updated_at: '2026-10-13T10:00:00.000Z',
  }
}

async function mountList(roles: ('UserAdmin' | 'ApplicationAdmin')[] = ['UserAdmin']) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe({
    ...user(0),
    directory_roles: roles,
    mfa: { totp: false, totp_pending: false, recovery_codes_remaining: 0 },
    features: { email: false },
  })
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/admin/users', name: 'admin-users', component: UsersList },
      { path: '/admin/users/:id', name: 'admin-user', component: UsersList },
    ],
  })
  const w = mount(UsersList, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return w
}

beforeEach(() => {
  list.mockReset()
})
afterEach(() => vi.useRealTimers())

describe('UsersList', () => {
  it('pages forward and back with cursors', async () => {
    list
      .mockResolvedValueOnce({ items: [user(1), user(2)], next_cursor: 'c2' })
      .mockResolvedValueOnce({ items: [user(3)], next_cursor: null })
      .mockResolvedValueOnce({ items: [user(1), user(2)], next_cursor: 'c2' })
    const w = await mountList()

    expect(w.findAll('tbody tr')).toHaveLength(2)
    expect(w.find('tbody').text()).toContain('Disabled')
    expect(w.find('a[href="/admin/users/u1"]').text()).toBe('User 1')
    const button = (name: string) => w.findAll('button').find((b) => b.text() === name)
    expect(button('Previous')?.attributes('disabled')).toBeDefined()

    await button('Next')?.trigger('click')
    await flushPromises()
    expect(list.mock.calls[1]?.[0]).toMatchObject({ cursor: 'c2' })
    expect(w.findAll('tbody tr')).toHaveLength(1)
    expect(w.text()).toContain('Page 2')
    expect(button('Next')?.attributes('disabled')).toBeDefined()

    await button('Previous')?.trigger('click')
    await flushPromises()
    expect(list.mock.calls[2]?.[0]).toMatchObject({ cursor: null })
    expect(w.findAll('tbody tr')).toHaveLength(2)
  })

  it('searches after typing stops', async () => {
    vi.useFakeTimers()
    list.mockResolvedValue({ items: [user(1)], next_cursor: null })
    const w = await mountList()
    await w.find('input[type=search]').setValue('ann')
    vi.advanceTimersByTime(300)
    await flushPromises()
    expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ search: 'ann', cursor: null }))
  })

  it('shows "New user" only to user administrators', async () => {
    list.mockResolvedValue({ items: [], next_cursor: null })
    const admin = await mountList(['UserAdmin'])
    expect(admin.text()).toContain('New user')
    expect(admin.text()).toContain('No users found.')
    const appAdmin = await mountList(['ApplicationAdmin'])
    expect(appAdmin.text()).not.toContain('New user')
  })

  it('shows a created user’s one-time password once and drops it on Done', async () => {
    list.mockResolvedValue({ items: [], next_cursor: null })
    const w = await mountList()
    const { default: CreateUserDialog } = await import('./CreateUserDialog.vue')
    w.findComponent(CreateUserDialog).vm.$emit('created', {
      user: user(9),
      one_time_password: 'one-time-pw-123',
      invite_sent: false,
    })
    await flushPromises()
    expect(w.find('[data-testid=secret-values]').text()).toBe('one-time-pw-123')
    await w.findAll('button').find((b) => b.text() === 'Done')?.trigger('click')
    await flushPromises()
    expect(w.find('[data-testid=secret-values]').exists()).toBe(false)
    expect(w.html()).not.toContain('one-time-pw-123')
  })

  it('confirms an invitation instead of showing a password', async () => {
    list.mockResolvedValue({ items: [], next_cursor: null })
    const w = await mountList()
    const { default: CreateUserDialog } = await import('./CreateUserDialog.vue')
    w.findComponent(CreateUserDialog).vm.$emit('created', {
      user: user(9),
      one_time_password: null,
      invite_sent: true,
    })
    await flushPromises()
    expect(w.find('[role=status]').text()).toBe('Invitation sent to user9@example.com.')
    expect(w.find('[data-testid=secret-values]').exists()).toBe(false)
  })

  it('shows a permission message on 403', async () => {
    const { ApiError } = await import('@/api/client')
    list.mockImplementation(async () => {
      throw new ApiError(403, { error: 'forbidden' })
    })
    const w = await mountList()
    expect(w.find('[role=alert]').text()).toMatch(/don't have permission/)
  })
})
