import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { fakeApp, fakeMe } from '@/test/helpers'

const applications = { list: vi.fn(), create: vi.fn() }
vi.mock('@/api/applications', () => ({ applications }))

const { default: AppsList } = await import('./AppsList.vue')
const { useAuthStore } = await import('@/stores/auth')

beforeEach(() => {
  Object.values(applications).forEach((f) => f.mockReset())
})

describe('AppsList', () => {
  it('marks apps managed by oauth apply', async () => {
    applications.list.mockResolvedValue({
      items: [fakeApp({ managed: true }), fakeApp({ id: 'a2', client_id: 'crm' })],
      next_cursor: null,
    })
    const pinia = createPinia()
    setActivePinia(pinia)
    useAuthStore().setMe(fakeMe({ directory_roles: ['ApplicationAdmin'] }))
    const blank = { render: () => null }
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/admin/apps', name: 'admin-apps', component: AppsList },
        { path: '/admin/apps/:id', name: 'admin-app', component: blank },
      ],
    })
    await router.push('/admin/apps')
    const w = mount(AppsList, { global: { plugins: [pinia, router] } })
    await flushPromises()

    const rows = w.findAll('tbody tr')
    expect(rows).toHaveLength(2)
    expect(rows[0]?.text()).toContain('Managed by apply')
    expect(rows[1]?.text()).not.toContain('Managed by apply')
  })
})
