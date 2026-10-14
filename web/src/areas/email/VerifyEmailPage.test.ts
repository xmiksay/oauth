import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { createPinia } from 'pinia'
import { mockFetch } from '@/test/helpers'
import VerifyEmailPage from './VerifyEmailPage.vue'

afterEach(() => vi.unstubAllGlobals())

async function mountAt(url: string): Promise<{ w: ReturnType<typeof mount>; router: Router }> {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/myaccount/verify-email', component: VerifyEmailPage },
      { path: '/myaccount', name: 'myaccount', component: { template: '<div />' } },
    ],
  })
  await router.push(url)
  const w = mount(VerifyEmailPage, { global: { plugins: [createPinia(), router] } })
  await flushPromises()
  return { w, router }
}

const confirmButton = (w: ReturnType<typeof mount>) =>
  w.findAll('button').find((b) => b.text() === 'Confirm email address')

describe('VerifyEmailPage', () => {
  it('strips the token and waits for a click before posting', async () => {
    const calls = mockFetch({ body: { purpose: 'verify', email: 'ann@example.com' } })
    const { w, router } = await mountAt('/myaccount/verify-email#token=v-tok')
    expect(router.currentRoute.value.fullPath).toBe('/myaccount/verify-email')
    expect(calls).toHaveLength(0)
    await confirmButton(w)?.trigger('click')
    await flushPromises()
    expect(calls[0]).toMatchObject({
      url: '/api/authn/email/verify',
      method: 'POST',
      body: { token: 'v-tok' },
    })
    expect(w.text()).toContain('Your email address ann@example.com is verified.')
  })

  it('names the new sign-in address after an email change', async () => {
    mockFetch({ body: { purpose: 'change', email: 'new@example.com' } })
    const { w } = await mountAt('/myaccount/verify-email#token=c-tok')
    await confirmButton(w)?.trigger('click')
    await flushPromises()
    expect(w.text()).toContain('Your sign-in email is now new@example.com.')
  })

  it('explains an invalid link and offers no retry', async () => {
    mockFetch({ status: 400, body: { error: 'invalid_token' } })
    const { w } = await mountAt('/myaccount/verify-email#token=old')
    await confirmButton(w)?.trigger('click')
    await flushPromises()
    expect(w.find('[role=alert]').text()).toBe(
      'This link is invalid, has expired or was already used.',
    )
    expect(confirmButton(w)).toBeUndefined()
  })

  it('reports an address taken meanwhile', async () => {
    mockFetch({ status: 409, body: { error: 'conflict' } })
    const { w } = await mountAt('/myaccount/verify-email#token=c-tok')
    await confirmButton(w)?.trigger('click')
    await flushPromises()
    expect(w.find('[role=alert]').text()).toMatch(/used by another account/)
  })
})
