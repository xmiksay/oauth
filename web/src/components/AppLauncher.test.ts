import { afterEach, describe, expect, it } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { DirectoryRole } from '@/api/types'
import { useAuthStore } from '@/stores/auth'
import { appsRouter, fakeMe } from '@/test/helpers'
import AppLauncher from './AppLauncher.vue'

let w: VueWrapper | null = null
afterEach(() => {
  w?.unmount()
  w = null
})

async function mountAt(path: string, roles: DirectoryRole[] = []) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ directory_roles: roles }))
  const router = appsRouter()
  await router.push(path)
  w = mount(AppLauncher, { global: { plugins: [pinia, router] }, attachTo: document.body })
  return { w, router }
}

const toggle = (w: VueWrapper) => w.get('button[aria-label="Switch app"]')
const menu = (w: VueWrapper) => w.get('#app-launcher')
const isOpen = (w: VueWrapper) => toggle(w).attributes('aria-expanded') === 'true'
const labels = (w: VueWrapper) => menu(w).findAll('a').map((a) => a.text().replace('✓', '').trim())

describe('AppLauncher', () => {
  it('lists the admin center only with a directory role', async () => {
    expect(labels((await mountAt('/myaccount')).w)).toEqual(['Dashboard', 'My Account'])
    w?.unmount()
    expect(labels((await mountAt('/myaccount', ['GlobalAdmin'])).w)).toEqual([
      'Dashboard',
      'My Account',
      'Admin center',
    ])
  })

  it('marks the current app', async () => {
    const { w } = await mountAt('/admin', ['ApplicationAdmin'])
    const current = menu(w).findAll('a[aria-current="page"]')
    expect(current.map((a) => a.attributes('href'))).toEqual(['/admin'])
  })

  it('opens on click and closes on Escape, an outside click or navigation', async () => {
    const { w, router } = await mountAt('/')
    expect(isOpen(w)).toBe(false)
    expect(menu(w).isVisible()).toBe(false)

    await toggle(w).trigger('click')
    expect(isOpen(w)).toBe(true)
    expect(menu(w).isVisible()).toBe(true)
    expect(document.activeElement).toBe(menu(w).find('a').element)

    await menu(w).find('a').trigger('keydown', { key: 'Escape' })
    expect(isOpen(w)).toBe(false)
    expect(document.activeElement).toBe(toggle(w).element)

    await toggle(w).trigger('click')
    document.body.dispatchEvent(new Event('pointerdown', { bubbles: true }))
    await flushPromises()
    expect(isOpen(w)).toBe(false)

    await toggle(w).trigger('click')
    await router.push('/myaccount')
    await flushPromises()
    expect(isOpen(w)).toBe(false)
  })
})
