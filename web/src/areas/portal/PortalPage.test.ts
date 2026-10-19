import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { DirectoryRole } from '@/api/types'
import { appsRouter, fakeMe } from '@/test/helpers'

const get = vi.fn()
vi.mock('@/api/me', () => ({ me: { get: () => get() } }))

const { default: PortalPage } = await import('./PortalPage.vue')

async function mountPortal(roles: DirectoryRole[]) {
  const pinia = createPinia()
  setActivePinia(pinia)
  get.mockResolvedValue(fakeMe({ display_name: 'Ann Admin', directory_roles: roles }))
  const router = appsRouter()
  await router.push('/')
  const w = mount(PortalPage, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return w
}

const main = (w: Awaited<ReturnType<typeof mountPortal>>) => w.get('main')
const tiles = (w: Awaited<ReturnType<typeof mountPortal>>) =>
  main(w)
    .findAll('h2')
    .map((h) => h.text())

describe('PortalPage', () => {
  it('greets the user and links to My Account and its sections', async () => {
    const w = await mountPortal([])
    expect(main(w).get('h1').text()).toBe('Hello, Ann Admin')
    const hrefs = main(w)
      .findAll('a')
      .map((a) => a.attributes('href'))
    expect(hrefs).toEqual([
      '/myaccount',
      '/myaccount/security',
      '/myaccount/sessions',
      '/myaccount/apps',
    ])
  })

  it('offers the admin center only with a directory role', async () => {
    expect(tiles(await mountPortal([]))).not.toContain('Admin center')
    const admin = await mountPortal(['UserAdmin'])
    expect(tiles(admin)).toContain('Admin center')
    expect(main(admin).find('a[href="/admin"]').exists()).toBe(true)
  })
})
