import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { h, nextTick } from 'vue'
import { fakeMe } from '@/test/helpers'
import { adminNav } from './nav'

const get = vi.fn()
vi.mock('@/api/me', () => ({ me: { get: () => get() } }))

const { default: AdminLayout } = await import('./AdminLayout.vue')

/** jsdom has no matchMedia: one fake query whose `change` the tests fire by hand. */
const mediaListeners = new Set<() => void>()
const fireMediaChange = () => mediaListeners.forEach((l) => l())
const mediaQueries: string[] = []

let w: VueWrapper | null = null
beforeEach(() => {
  mediaQueries.length = 0
  vi.stubGlobal('matchMedia', (query: string) => {
    mediaQueries.push(query)
    return {
      addEventListener: (_: string, l: () => void) => mediaListeners.add(l),
      removeEventListener: (_: string, l: () => void) => mediaListeners.delete(l),
    }
  })
})
afterEach(() => {
  w?.unmount()
  w = null
  vi.unstubAllGlobals()
})

/** The admin center at `/admin`, whose page holds a text input. */
async function mountAdmin() {
  const pinia = createPinia()
  setActivePinia(pinia)
  get.mockResolvedValue(fakeMe({ directory_roles: ['GlobalAdmin'] }))
  const blank = { render: () => null }
  const page = { render: () => h('input', { id: 'in-main' }) }
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
  return Object.assign(w, { router })
}

const navToggle = (w: VueWrapper) => w.get('button[aria-label="Toggle navigation"]')
const navOpen = (w: VueWrapper) => navToggle(w).attributes('aria-expanded') === 'true'
const launcherToggle = (w: VueWrapper) => w.get('button[aria-label="Switch app"]')
const launcherOpen = (w: VueWrapper) => launcherToggle(w).attributes('aria-expanded') === 'true'

async function focusAndEscape(el: HTMLElement) {
  el.focus()
  el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
  await nextTick()
}

describe('AdminLayout', () => {
  it('opening the side nav focuses its first link, so Escape works right away', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    await nextTick()
    const first = w.get('#side-nav a').element
    expect(document.activeElement).toBe(first)
    const esc = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })
    first.dispatchEvent(esc)
    await nextTick()
    expect(esc.defaultPrevented).toBe(true)
    expect(navOpen(w)).toBe(false)
    expect(document.activeElement).toBe(navToggle(w).element)
  })

  it('Escape inside the side nav closes it and focuses its toggle', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    expect(navOpen(w)).toBe(true)
    await focusAndEscape(w.get('#side-nav a').element as HTMLElement)
    expect(navOpen(w)).toBe(false)
    expect(document.activeElement).toBe(navToggle(w).element)
  })

  it('Escape on document with focus fallen to body closes the side nav', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    await nextTick()
    ;(document.activeElement as HTMLElement).blur()
    expect(document.activeElement).toBe(document.body)
    const esc = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })
    document.dispatchEvent(esc)
    await nextTick()
    expect(esc.defaultPrevented).toBe(true)
    expect(navOpen(w)).toBe(false)
    expect(document.activeElement).toBe(navToggle(w).element)
  })

  it('Escape with focus on the menu toggle closes the side nav', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    await nextTick()
    const toggle = navToggle(w).element as HTMLElement
    toggle.focus()
    expect(navOpen(w)).toBe(true)
    const esc = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })
    toggle.dispatchEvent(esc)
    await nextTick()
    expect(esc.defaultPrevented).toBe(true)
    expect(navOpen(w)).toBe(false)
    expect(document.activeElement).toBe(toggle)
  })

  it('leaves the side nav open, and focus put, on an Escape from the main content', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    await nextTick()
    // Via body: focus moving straight from the nav to the content would already close it.
    ;(document.activeElement as HTMLElement).blur()
    const input = w.get('#in-main').element as HTMLElement
    await focusAndEscape(input)
    expect(navOpen(w)).toBe(true)
    expect(document.activeElement).toBe(input)
  })

  it('moves no focus on an Escape while the side nav is closed', async () => {
    const w = await mountAdmin()
    const link = w.get('#side-nav a').element as HTMLElement
    await focusAndEscape(link)
    expect(document.activeElement).toBe(link)
    const input = w.get('#in-main').element as HTMLElement
    await focusAndEscape(input)
    expect(document.activeElement).toBe(input)
  })

  it('Escape with focus on body closes the app launcher but not the side nav', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    await nextTick()
    // Focus to nowhere (null) keeps the nav; straight into the launcher would close it.
    ;(document.activeElement as HTMLElement).blur()
    await launcherToggle(w).trigger('click')
    await nextTick()
    expect(launcherOpen(w)).toBe(true)
    ;(document.activeElement as HTMLElement).blur()
    expect(document.activeElement).toBe(document.body)
    expect(navOpen(w)).toBe(true)

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    await nextTick()
    expect(launcherOpen(w)).toBe(false)
    expect(navOpen(w)).toBe(true)
  })

  it('closes the side nav when focus leaves it for the main content', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    await nextTick()
    const input = w.get('#in-main').element as HTMLElement
    input.focus()
    await nextTick()
    expect(navOpen(w)).toBe(false)
    expect(document.activeElement).toBe(input)
  })

  it('keeps the side nav open while focus moves within it or to its toggle', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    await nextTick()
    ;(w.findAll('#side-nav a')[1]?.element as HTMLElement).focus()
    await nextTick()
    expect(navOpen(w)).toBe(true)
    ;(navToggle(w).element as HTMLElement).focus()
    await nextTick()
    expect(navOpen(w)).toBe(true)
  })

  it('a nav link closes the overlay and moves focus to the main content', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    await nextTick()
    await w.findAll('#side-nav a')[1]?.trigger('click')
    await flushPromises()
    expect(w.router.currentRoute.value.name).toBe(adminNav[0]?.name)
    expect(navOpen(w)).toBe(false)
    expect(document.activeElement).toBe(w.get('main').element)
  })

  it('leaves focus alone on a route change with the side nav closed', async () => {
    const w = await mountAdmin()
    const launcher = launcherToggle(w).element as HTMLElement
    launcher.focus()
    await w.router.push({ name: adminNav[0]?.name })
    await flushPromises()
    expect(document.activeElement).toBe(launcher)
  })

  it('closes the side nav when the viewport crosses the md breakpoint', async () => {
    const layout = await mountAdmin()
    expect(mediaQueries).toEqual(['(min-width: 48rem)'])
    await navToggle(layout).trigger('click')
    fireMediaChange()
    await nextTick()
    expect(navOpen(layout)).toBe(false)
    layout.unmount()
    w = null
    expect(mediaListeners.size).toBe(0)
  })

  it('a backdrop click closes the side nav and focuses its toggle', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    await nextTick()
    await w.get('[aria-hidden=true].z-backdrop').trigger('click')
    await nextTick()
    expect(navOpen(w)).toBe(false)
    expect(document.activeElement).toBe(navToggle(w).element)
  })

  it('crossing md with focus in the side nav leaves it there (the nav stays visible)', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    await nextTick()
    const link = document.activeElement
    expect(w.get('#side-nav').element.contains(link)).toBe(true)
    fireMediaChange()
    await nextTick()
    expect(navOpen(w)).toBe(false)
    expect(document.activeElement).toBe(link)
  })

  it('crossing md with focus outside the side nav leaves it put', async () => {
    const w = await mountAdmin()
    await navToggle(w).trigger('click')
    await nextTick()
    const toggle = navToggle(w).element as HTMLElement
    toggle.focus()
    fireMediaChange()
    await nextTick()
    expect(navOpen(w)).toBe(false)
    expect(document.activeElement).toBe(toggle)
  })
})
