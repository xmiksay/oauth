import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import type { Application } from '@/api/types'
import { fakeApp, fakeMe } from '@/test/helpers'

const applications = { get: vi.fn(), update: vi.fn() }
vi.mock('@/api/applications', () => ({ applications }))

const { default: AppDetail } = await import('./AppDetail.vue')
const { useAuthStore } = await import('@/stores/auth')

const WARNING = 'are overwritten by the next apply'

async function mountPage(app: Application) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ directory_roles: ['ApplicationAdmin'] }))
  applications.get.mockResolvedValue(app)
  const blank = { render: () => null }
  const names = ['auth', 'secrets', 'token', 'expose', 'roles', 'permissions']
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/admin/apps', name: 'admin-apps', component: blank },
      {
        path: '/admin/apps/:id',
        component: AppDetail,
        children: [
          { path: '', name: 'admin-app', component: blank },
          ...names.map((n) => ({ path: n, name: `admin-app-${n}`, component: blank })),
        ],
      },
    ],
  })
  await router.push(`/admin/apps/${app.id}`)
  const w = mount(AppDetail, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return w
}

beforeEach(() => {
  Object.values(applications).forEach((f) => f.mockReset())
})

describe('AppDetail', () => {
  it('warns only on apps managed by oauth apply', async () => {
    const plain = await mountPage(fakeApp())
    expect(plain.text()).toContain('Client ID hr')
    expect(plain.text()).not.toContain(WARNING)

    const managed = await mountPage(fakeApp({ managed: true }))
    expect(managed.text()).toContain('Managed by oauth apply')
    expect(managed.text()).toContain(WARNING)
  })
})
