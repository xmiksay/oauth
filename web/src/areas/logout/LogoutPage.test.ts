import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { mockFetch } from '@/test/helpers'
import LogoutPage from './LogoutPage.vue'

afterEach(() => vi.unstubAllGlobals())

async function mountAt(url: string) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/:tenant/logout', component: LogoutPage }],
  })
  await router.push(url)
  return mount(LogoutPage, { global: { plugins: [router] } })
}

describe('LogoutPage', () => {
  it('asks to confirm, then POSTs and shows the signed-out state', async () => {
    const calls = mockFetch({ body: { signed_out: true } })
    const w = await mountAt('/contoso/logout')
    expect(w.find('h1').text()).toBe('Sign out?')
    await w.find('button').trigger('click')
    await flushPromises()
    expect(calls[0]).toMatchObject({ url: '/contoso/oauth2/logout', method: 'POST', body: {} })
    expect(w.find('h1').text()).toBe('You have been signed out')
    expect(w.find('button').exists()).toBe(false)
  })

  it('still offers sign-out on ?signed_out=1 (the link alone proves nothing)', async () => {
    const calls = mockFetch({ body: { signed_out: true } })
    const w = await mountAt('/contoso/logout?signed_out=1')
    expect(w.find('h1').text()).toBe('You have been signed out')
    await w.find('button').trigger('click')
    await flushPromises()
    expect(calls).toHaveLength(1)
  })
})
