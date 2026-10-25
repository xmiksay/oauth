import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { h } from 'vue'
import { fakeMe } from '@/test/helpers'
import { adminNav } from './nav'

const get = vi.fn()
vi.mock('@/api/me', () => ({ me: { get: () => get() } }))

const { default: AdminLayout } = await import('./AdminLayout.vue')

let w: VueWrapper | null = null
afterEach(() => {
  w?.unmount()
  w = null
})

/** The admin center at `/admin`, whose page holds an open `<dialog>` with a button. */
async function mountAdmin() {
  const pinia = createPinia()
  setActivePinia(pinia)
  get.mockResolvedValue(fakeMe({ directory_roles: ['GlobalAdmin'] }))
  const blank = { render: () => null }
  const page = { render: () => h('dialog', { open: true }, [h('button', { id: 'in-dialog' })]) }
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', name: 'portal', component: blank },
      { path: '/myaccount', name: 'myaccount', component: blank },
      { path: '/admin', name: 'admin', component: page },
      ...adminNav.map((i) => ({ path: `/admin/${i.path}`, name: i.name, component: blank })),
    ],
  })
  await router.push('/admin')
  w = mount(AdminLayout, { global: { plugins: [pinia, router] }, attachTo: document.body })
  await flushPromises()
  return w
}

const navToggle = (w: VueWrapper) => w.get('button[aria-label="Toggle navigation"]')
const navOpen = (w: VueWrapper) => navToggle(w).attributes('aria-expanded') === 'true'
const launcherToggle = (w: VueWrapper) => w.get('button[aria-label="Switch app"]')
const launcherOpen = (w: VueWrapper) => launcherToggle(w).attributes('aria-expanded') === 'true'

describe('AdminLayout', () => {
  it('Escape closes the app launcher first, then the side nav (focus back on its toggle)', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    expect(navOpen(w)).toBe(true)
    await launcherToggle(w).trigger('click')
    expect(launcherOpen(w)).toBe(true)

    await w.get('#app-launcher a').trigger('keydown', { key: 'Escape' })
    expect(launcherOpen(w)).toBe(false)
    expect(navOpen(w)).toBe(true)

    await launcherToggle(w).trigger('keydown', { key: 'Escape' })
    expect(navOpen(w)).toBe(false)
    expect(document.activeElement).toBe(navToggle(w).element)
  })

  it('leaves the side nav open on an Escape inside a dialog', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    await w.get('#in-dialog').trigger('keydown', { key: 'Escape' })
    expect(navOpen(w)).toBe(true)
  })
})
