import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { createPinia } from 'pinia'
import { mockFetch } from '@/test/helpers'

const navigateTo = vi.fn()
vi.mock('@/lib/navigate', async (orig) => ({
  ...(await orig<typeof import('@/lib/navigate')>()),
  navigateTo,
}))

const { default: DevicePage } = await import('./DevicePage.vue')

afterEach(() => {
  vi.unstubAllGlobals()
  navigateTo.mockReset()
})

async function mountAt(url: string): Promise<{ w: ReturnType<typeof mount>; router: Router }> {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/device', component: DevicePage }],
  })
  await router.push(url)
  const w = mount(DevicePage, { global: { plugins: [createPinia(), router] } })
  await flushPromises()
  return { w, router }
}

describe('DevicePage', () => {
  it('prefills the code from the link, strips it from the URL and waits for a click', async () => {
    const calls = mockFetch({ body: { redirect: 'https://contoso.example/login?tx=t1' } })
    const { w, router } = await mountAt('/device?user_code=BDFG-KLMN')
    expect(router.currentRoute.value.fullPath).toBe('/device')
    expect((w.find('input').element as HTMLInputElement).value).toBe('BDFG-KLMN')
    expect(calls).toHaveLength(0)
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(calls[0]).toMatchObject({
      url: '/api/authn/device',
      method: 'POST',
      body: { user_code: 'BDFG-KLMN' },
    })
    expect(navigateTo).toHaveBeenCalledWith('https://contoso.example/login?tx=t1')
  })

  it('explains a wrong code and keeps the form', async () => {
    mockFetch({ status: 401, body: { error: 'invalid_code' } })
    const { w } = await mountAt('/device')
    await w.find('input').setValue('bdfg klmn')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.find('[role=alert]').text()).toMatch(/invalid or has expired/)
    expect(navigateTo).not.toHaveBeenCalled()
    expect(w.find('button').attributes('disabled')).toBeUndefined()
  })

  it('reports rate limiting', async () => {
    mockFetch({ status: 429, body: { error: 'rate_limited' }, headers: { 'retry-after': '60' } })
    const { w } = await mountAt('/device')
    await w.find('input').setValue('BDFG-KLMN')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.find('[role=alert]').text()).toMatch(/Too many attempts/)
  })

  it('never follows a non-web redirect', async () => {
    mockFetch({ body: { redirect: 'javascript:alert(1)' } })
    const { w } = await mountAt('/device')
    await w.find('input').setValue('BDFG-KLMN')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(navigateTo).not.toHaveBeenCalled()
  })

  it('confirms an approved device', async () => {
    const { w } = await mountAt('/device?result=approved')
    expect(w.text()).toContain('Your device is now signed in')
    expect(w.find('form').exists()).toBe(false)
  })

  it('explains how a sign-in ended and offers the form again', async () => {
    const cases: [string, RegExp][] = [
      ['access_denied', /You denied the sign-in/],
      ['consent_required', /administrator must approve/],
      ['expired_token', /code expired/],
      ['login_required', /session ended/],
      ['not_assigned', /aren't assigned/],
      ['other', /didn't complete/],
    ]
    for (const [code, text] of cases) {
      const { w } = await mountAt(`/device?error=${code}`)
      expect(w.find('[role=alert]').text()).toMatch(text)
      expect(w.find('form').exists()).toBe(true)
      w.unmount()
    }
  })
})
