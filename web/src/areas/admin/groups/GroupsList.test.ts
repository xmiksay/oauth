import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { ApiError } from '@/api/client'
import { fakeMe } from '@/test/helpers'

const groups = { list: vi.fn(), create: vi.fn() }
vi.mock('@/api/directory', () => ({ groups }))

const { default: GroupsList } = await import('./GroupsList.vue')
const { useAuthStore } = await import('@/stores/auth')

async function mountList() {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ directory_roles: ['UserAdmin'] }))
  const blank = { render: () => null }
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/admin/groups', name: 'admin-groups', component: GroupsList },
      { path: '/admin/groups/:id', name: 'admin-group', component: blank },
    ],
  })
  await router.push('/admin/groups')
  const w = mount(GroupsList, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return { w, router }
}

beforeEach(() => {
  Object.values(groups).forEach((f) => f.mockReset())
  groups.list.mockResolvedValue({ items: [], next_cursor: null })
})

describe('GroupsList', () => {
  it('keeps the create dialog open with a taken name (409)', async () => {
    const { w, router } = await mountList()
    groups.create.mockRejectedValue(
      new ApiError(409, {
        error: 'conflict',
        error_description: 'another group already has this name (letter case is ignored)',
      }),
    )
    await w.findAll('button').find((b) => b.text() === 'New group')?.trigger('click')
    await flushPromises()
    await w.find('#cg-name').setValue('  ops ')
    await w.find('#create-group').trigger('submit')
    await flushPromises()

    expect(groups.create).toHaveBeenCalledWith({ display_name: 'ops' })
    expect(w.find('#create-group [role=alert]').text()).toContain('already has this name')
    expect(w.find('dialog').attributes('open')).toBeDefined()
    expect((w.find('#cg-name').element as HTMLInputElement).value).toBe('  ops ')
    expect(router.currentRoute.value.name).toBe('admin-groups')
  })
})
