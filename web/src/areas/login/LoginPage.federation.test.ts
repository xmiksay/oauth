import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { createPinia } from 'pinia'
import type { TxView } from '@/api/authn'
import { view } from './flowFixtures'
import { UPSTREAM_EXPIRED, upstreamErrorMessage } from './federation'

const api = {
  get: vi.fn(),
  password: vi.fn(),
  passkeyOptions: vi.fn(),
  passkey: vi.fn(),
  federation: vi.fn(),
  discover: vi.fn(),
}
vi.mock('@/api/authn', async (orig) => ({
  ...(await orig<typeof import('@/api/authn')>()),
  authn: api,
}))
const navigateTo = vi.fn()
vi.mock('@/lib/navigate', async (orig) => ({
  ...(await orig<typeof import('@/lib/navigate')>()),
  navigateTo,
}))

const { default: LoginPage } = await import('./LoginPage.vue')

const ENTRA = { id: 'idp1', name: 'Entra' }
const UPSTREAM = 'https://login.example.com/authorize?state=s'

async function mountPage(url = '/login?tx=tx-1') {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/login', component: LoginPage }],
  })
  await router.push(url)
  const w = mount(LoginPage, {
    global: { plugins: [createPinia(), router] },
    attachTo: document.body,
  })
  await flushPromises()
  return w
}

const button = (w: Awaited<ReturnType<typeof mountPage>>, text: string) =>
  w.findAll('button').find((b) => b.text() === text)

const withFederation = (extra: Partial<TxView> = {}) =>
  view('password', { features: { password_reset: false, federation: true }, ...extra })

beforeEach(() => {
  Object.values(api).forEach((f) => f.mockReset())
  navigateTo.mockReset()
  api.federation.mockResolvedValue({ redirect: UPSTREAM })
})
afterEach(() => {
  document.body.innerHTML = ''
})

describe('LoginPage federation', () => {
  it('signs in with a provider button through a full-page redirect', async () => {
    let answer: (r: { redirect: string }) => void = () => {}
    api.federation.mockReturnValue(new Promise((resolve) => (answer = resolve)))
    api.get.mockResolvedValue(view('password', { idps: [ENTRA, { id: 'idp2', name: 'Okta' }] }))
    const w = await mountPage()
    expect(w.text()).toContain('or')
    await button(w, 'Sign in with Entra')?.trigger('click')
    expect(w.text()).toContain('Redirecting to Entra…')
    expect(w.find('form').exists()).toBe(false)
    answer({ redirect: UPSTREAM })
    await flushPromises()
    expect(api.federation).toHaveBeenCalledWith('tx-1', 'idp1')
    expect(navigateTo).toHaveBeenCalledWith(UPSTREAM)
  })

  it('suggests the provider of the typed email domain without blocking the form', async () => {
    api.get.mockResolvedValue(withFederation())
    api.discover.mockResolvedValue({ idp: ENTRA })
    const w = await mountPage()
    expect(w.find('[data-testid=idp-suggestion]').exists()).toBe(false)
    await w.find('#login-email').setValue('ann@contoso.com')
    await w.find('#login-email').trigger('blur')
    await flushPromises()
    expect(api.discover).toHaveBeenCalledWith('tx-1', 'ann@contoso.com')
    const box = w.find('[data-testid=idp-suggestion]')
    expect(box.text()).toContain('Your organization signs in with Entra.')
    expect(w.find('button[type=submit]').attributes('disabled')).toBeUndefined()
    await button(w, 'Continue with Entra')?.trigger('click')
    await flushPromises()
    expect(api.federation).toHaveBeenCalledWith('tx-1', 'idp1')
    expect(navigateTo).toHaveBeenCalledWith(UPSTREAM)
  })

  it('redirects to the hinted provider without a click', async () => {
    api.get.mockResolvedValue(view('password', { idp_hint: ENTRA }))
    await mountPage()
    expect(api.federation).toHaveBeenCalledWith('tx-1', 'idp1')
    expect(navigateTo).toHaveBeenCalledWith(UPSTREAM)
  })

  it.each(['account_exists', 'upstream_no_email', 'not_linked', 'upstream_failed', 'odd'])(
    'shows the %s error and offers the hinted provider as a button instead',
    async (code) => {
      api.get.mockResolvedValue(view('password', { idp_hint: ENTRA }))
      const w = await mountPage(`/login?tx=tx-1&error=${code}`)
      expect(api.federation).not.toHaveBeenCalled()
      expect(w.find('[role=alert]').text()).toBe(upstreamErrorMessage(code))
      expect(button(w, 'Sign in with Entra')).toBeDefined()
    },
  )

  it('explains an upstream failure that lost its transaction', async () => {
    const w = await mountPage('/login?error=upstream_failed')
    expect(api.get).not.toHaveBeenCalled()
    expect(w.find('[role=alert]').text()).toBe(UPSTREAM_EXPIRED)
  })

  it('links an upstream identity by signing in to the existing account', async () => {
    api.get.mockResolvedValue(view('link', { idps: [ENTRA] }))
    api.password.mockResolvedValue({ redirect: 'https://shop.example/cb?code=c' })
    const w = await mountPage()
    expect(w.find('h1').text()).toBe('Link your Entra account')
    expect(w.find('[data-testid=link-intro]').text()).toBe(
      'Sign in with your existing account to link ann@contoso.com from Entra. Next time you can sign in with Entra directly.',
    )
    expect(button(w, 'Sign in with Entra')).toBeUndefined()
    expect((w.find('#login-email').element as HTMLInputElement).value).toBe('ann@contoso.com')
    await w.find('#login-email').trigger('blur')
    await w.find('#login-password').setValue('pw')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(api.discover).not.toHaveBeenCalled()
    expect(api.password).toHaveBeenCalledWith('tx-1', 'ann@contoso.com', 'pw')
    expect(navigateTo).toHaveBeenCalledWith('https://shop.example/cb?code=c')
  })

  it('names no provider when the link has none', async () => {
    api.get.mockResolvedValue(
      view('link', { link: { idp: null, email: null, name: null } }),
    )
    const w = await mountPage()
    expect(w.find('h1').text()).toBe('Link your identity provider account')
    expect(w.find('[data-testid=link-intro]').text()).toBe(
      'Sign in with your existing account to link this identity from the identity provider. Next time you can sign in with the identity provider directly.',
    )
  })

  it('shows a dropped link above the password form', async () => {
    api.get.mockResolvedValue(view('password', { notice: 'link_unavailable' }))
    const w = await mountPage()
    expect(w.find('[role=status]').text()).toBe(
      'The identity provider is no longer available. Sign in normally.',
    )
    expect(w.find('#login-password').exists()).toBe(true)
  })
})
