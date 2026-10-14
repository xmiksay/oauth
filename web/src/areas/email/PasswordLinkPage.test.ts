import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { createPinia } from 'pinia'
import { CREATION_OPTIONS, REGISTRATION_JSON, domError, mockFetch, stubWebAuthn } from '@/test/helpers'
import PasswordLinkPage from './PasswordLinkPage.vue'

afterEach(() => vi.unstubAllGlobals())

const blank = { template: '<div />' }

async function mountAt(url: string): Promise<{ w: ReturnType<typeof mount>; router: Router }> {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/login/reset', component: PasswordLinkPage, props: { mode: 'reset' } },
      { path: '/login/invite', component: PasswordLinkPage, props: { mode: 'invite' } },
      { path: '/myaccount', name: 'myaccount', component: blank },
    ],
  })
  await router.push(url)
  const mode = url.startsWith('/login/reset') ? 'reset' : 'invite'
  const w = mount(PasswordLinkPage, {
    props: { mode },
    global: { plugins: [createPinia(), router] },
  })
  await flushPromises()
  return { w, router }
}

async function fill(w: ReturnType<typeof mount>, pw: string, confirm = pw) {
  await w.find('#link-password').setValue(pw)
  await w.find('#link-confirm').setValue(confirm)
  await w.find('form').trigger('submit')
  await flushPromises()
}

async function passkeyInstead(w: ReturnType<typeof mount>) {
  await w.findAll('button').find((b) => b.text() === 'Create a passkey instead')?.trigger('click')
  await flushPromises()
}

describe('PasswordLinkPage', () => {
  it('drops the token from the URL at once, keeping other parameters', async () => {
    mockFetch()
    const { router } = await mountAt('/login/reset?lang=en#token=secret-tok')
    expect(router.currentRoute.value.fullPath).toBe('/login/reset?lang=en')
    expect(router.currentRoute.value.hash).toBe('')
  })

  it('resets the password with the token and says the user was signed out', async () => {
    const calls = mockFetch({ status: 204 })
    const { w } = await mountAt('/login/reset#token=secret-tok')
    await fill(w, 'a-long-new-password')
    expect(calls[0]).toMatchObject({
      url: '/api/authn/email/reset',
      method: 'POST',
      body: { token: 'secret-tok', new_password: 'a-long-new-password' },
    })
    expect(w.text()).toContain('signed out everywhere')
    expect(w.find('a[href="/myaccount"]').exists()).toBe(true)
    expect(w.find('form').exists()).toBe(false)
  })

  it('accepts an invitation through its own endpoint', async () => {
    const calls = mockFetch({ status: 204 })
    const { w } = await mountAt('/login/invite#token=inv-tok')
    expect(w.find('h1').text()).toBe('Set your password')
    await fill(w, 'a-long-new-password')
    expect(calls[0]).toMatchObject({ url: '/api/authn/email/invite', body: { token: 'inv-tok' } })
    expect(w.find('h1').text()).toBe('Your account is ready')
  })

  it('checks the password locally before posting', async () => {
    const calls = mockFetch()
    const { w } = await mountAt('/login/reset#token=t')
    await fill(w, 'short')
    expect(w.find('[role=alert]').text()).toMatch(/at least 12/)
    await fill(w, 'a-long-new-password', 'a-long-new-passw0rd')
    expect(w.find('[role=alert]').text()).toMatch(/do not match/)
    expect(calls).toHaveLength(0)
  })

  it('explains a dead link and hides the form', async () => {
    mockFetch({ status: 400, body: { error: 'invalid_token', error_description: 'x' } })
    const { w } = await mountAt('/login/reset#token=used')
    await fill(w, 'a-long-new-password')
    expect(w.find('[role=alert]').text()).toBe(
      'This link is invalid, has expired or was already used.',
    )
    expect(w.find('form').exists()).toBe(false)
  })

  it('treats a link without a token as invalid', async () => {
    const { w } = await mountAt('/login/invite')
    expect(w.find('[role=alert]').text()).toMatch(/invalid, has expired/)
    expect(w.find('form').exists()).toBe(false)
  })

  it('offers a passkey only on invitations, and only where the browser has WebAuthn', async () => {
    const instead = (w: ReturnType<typeof mount>) => w.text().includes('Create a passkey instead')
    expect(instead((await mountAt('/login/invite#token=t')).w)).toBe(false)
    stubWebAuthn()
    expect(instead((await mountAt('/login/invite#token=t')).w)).toBe(true)
    expect(instead((await mountAt('/login/reset#token=t')).w)).toBe(false)
  })

  it('accepts an invitation with a new passkey', async () => {
    const { create } = stubWebAuthn()
    const calls = mockFetch({ body: CREATION_OPTIONS }, { status: 204 })
    const { w } = await mountAt('/login/invite#token=inv-tok')
    await passkeyInstead(w)
    expect(create).toHaveBeenCalledTimes(1)
    expect(calls.map((c) => [c.url, c.body])).toEqual([
      ['/api/authn/email/invite/passkey/options', { token: 'inv-tok' }],
      ['/api/authn/email/invite/passkey', { token: 'inv-tok', credential: REGISTRATION_JSON }],
    ])
    expect(w.find('h1').text()).toBe('Your account is ready')
    expect(w.text()).toContain('sign in with your passkey')
  })

  it('maps passkey failures: dead link, rejected credential, dismissed dialog', async () => {
    const { create } = stubWebAuthn()
    mockFetch(
      { body: CREATION_OPTIONS },
      { status: 400, body: { error: 'invalid_request', error_description: 'bad attestation' } },
      { body: CREATION_OPTIONS },
      { status: 400, body: { error: 'invalid_token' } },
    )
    const { w } = await mountAt('/login/invite#token=t')
    await passkeyInstead(w)
    expect(w.find('[role=alert]').text()).toBe("That passkey couldn't be registered.")

    create.mockRejectedValueOnce(domError('NotAllowedError'))
    await passkeyInstead(w)
    expect(w.find('[role=alert]').exists()).toBe(false)
    expect(w.find('[role=status]').text()).toBe('Passkey creation was cancelled.')

    await passkeyInstead(w)
    expect(w.find('[role=alert]').text()).toMatch(/invalid, has expired/)
    expect(w.find('form').exists()).toBe(false)
  })

  it('keeps the form for a rejected password (invalid_request)', async () => {
    mockFetch({
      status: 400,
      body: { error: 'invalid_request', error_description: 'password too long' },
    })
    const { w } = await mountAt('/login/reset#token=t')
    await fill(w, 'a-long-new-password')
    expect(w.find('[role=alert]').text()).toBe('password too long')
    expect(w.find('form').exists()).toBe(true)
  })
})
