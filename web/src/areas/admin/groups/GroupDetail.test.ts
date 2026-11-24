import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { ApiError } from '@/api/client'
import type { Group } from '@/api/types'
import { fakeMe } from '@/test/helpers'

const groups = {
  get: vi.fn(),
  update: vi.fn(),
  members: vi.fn(),
  addMember: vi.fn(),
  removeMember: vi.fn(),
  remove: vi.fn(),
}
vi.mock('@/api/directory', () => ({ groups, users: { list: vi.fn() } }))
vi.mock('@/api/applications', () => ({ applications: { list: vi.fn() } }))

const { default: GroupDetail } = await import('./GroupDetail.vue')
const { useAuthStore } = await import('@/stores/auth')

const group: Group = {
  id: 'g1',
  display_name: 'Ops',
  description: null,
  managed: false,
  created_at: '',
  updated_at: '',
}

async function mountDetail() {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ directory_roles: ['UserAdmin'] }))
  const blank = { render: () => null }
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/admin/groups', name: 'admin-groups', component: blank },
      { path: '/admin/groups/:id', name: 'admin-group', component: GroupDetail },
      { path: '/admin/users/:id', name: 'admin-user', component: blank },
    ],
  })
  await router.push('/admin/groups/g1')
  const w = mount(GroupDetail, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return w
}

beforeEach(() => {
  Object.values(groups).forEach((f) => f.mockReset())
  groups.get.mockResolvedValue(group)
  groups.members.mockResolvedValue({ items: [], next_cursor: null })
})

const member = {
  email: 'pat@example.com',
  display_name: 'Pat',
  user_type: 'member' as const,
  email_verified: true,
  disabled: false,
  must_change_password: false,
  has_password: false,
  managed: false,
  created_at: '',
  updated_at: '',
}

describe('GroupDetail', () => {
  it('marks memberships a group mapping keeps', async () => {
    groups.members.mockResolvedValue({
      items: [
        { ...member, id: 'u1', manual: true, idp_id: null },
        { ...member, id: 'u2', manual: false, idp_id: 'idp1' },
        { ...member, id: 'u3', manual: true, idp_id: 'idp1' },
      ],
      next_cursor: null,
    })
    const w = await mountDetail()
    const badges = w.findAll('[data-testid=mapped-badge]').map((b) => b.text())
    expect(badges).toEqual(['Group mapping', 'Manual + mapping'])
    expect(w.findAll('tbody tr')[1]?.find('[data-testid=mapped-badge]').attributes('title')).toContain(
      'next sign-in',
    )
  })

  it('warns that apply manages the group only when it does', async () => {
    const plain = await mountDetail()
    expect(plain.find('[data-testid=managed-note]').exists()).toBe(false)

    groups.get.mockResolvedValue({ ...group, managed: true })
    const managed = await mountDetail()
    const note = managed.find('[data-testid=managed-note]')
    expect(note.text()).toContain('Managed by oauth apply')
    expect(note.text()).toContain('declared members')
    expect(note.text()).toContain('beyond letter case')
  })

  it('shows a taken name (409) in the properties form', async () => {
    const w = await mountDetail()
    groups.update.mockRejectedValue(
      new ApiError(409, {
        error: 'conflict',
        error_description: 'another group already has this name (letter case is ignored)',
      }),
    )
    await w.find('#gd-name').setValue('Approvers')
    await w.find('form').trigger('submit')
    await flushPromises()

    expect(groups.update).toHaveBeenCalledWith('g1', { display_name: 'Approvers', description: '' })
    const alert = w.find('form [role=alert]')
    expect(alert.text()).toContain('already has this name')
    expect(w.find('#gd-name-hint').text()).toContain('ignoring letter case')
  })
})
