import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { ApiError } from '@/api/client'
import type { MyIdentities } from '@/api/types'
import { fakeMe } from '@/test/helpers'

const api = {
  identities: vi.fn(),
  linkIdentity: vi.fn(),
  unlinkIdentity: vi.fn(),
  reauthOptions: vi.fn(),
}
vi.mock('@/api/me', () => ({ me: api }))
const navigateTo = vi.fn()
vi.mock('@/lib/navigate', async (orig) => ({
  ...(await orig<typeof import('@/lib/navigate')>()),
  navigateTo,
}))

const { default: LinkedAccountsSection } = await import('./LinkedAccountsSection.vue')
const { useAuthStore } = await import('@/stores/auth')

const IDENTITIES: MyIdentities = {
  items: [
    {
      id: 'li1',
      idp_id: 'idp1',
      idp_name: 'Entra',
      email: 'ann@contoso.com',
      linked_at: '2026-10-01T10:00:00Z',
      last_used_at: null,
    },
  ],
  available: [{ id: 'idp2', name: 'Google' }],
}

let router: Router

async function mountSection(url = '/myaccount/security') {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe())
  router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/myaccount/security', component: LinkedAccountsSection }],
  })
  await router.push(url)
  const w = mount(LinkedAccountsSection, {
    global: { plugins: [pinia, router] },
    attachTo: document.body,
  })
  await flushPromises()
  return w
}

async function click(w: ReturnType<typeof mount>, text: string) {
  await w
    .findAll('button')
    .find((b) => b.text() === text)
    ?.trigger('click')
  await flushPromises()
}

async function confirmPassword(w: ReturnType<typeof mount>) {
  await w.find('#pp-password').setValue('pw')
  await w.find('#reauth-prompt').trigger('submit')
  await flushPromises()
}

beforeEach(() => {
  Object.values(api).forEach((f) => f.mockReset())
  navigateTo.mockReset()
  api.identities.mockResolvedValue(IDENTITIES)
})
afterEach(() => {
  document.body.innerHTML = ''
})

describe('LinkedAccountsSection', () => {
  it('is hidden while there is nothing to link', async () => {
    api.identities.mockResolvedValue({ items: [], available: [] })
    const w = await mountSection()
    expect(w.find('section').exists()).toBe(false)
  })

  it('links: re-auth, then a full-page redirect to the provider', async () => {
    api.linkIdentity.mockResolvedValue({ redirect: 'https://accounts.google.example/auth?x=1' })
    const w = await mountSection()
    expect(w.text()).toContain('ann@contoso.com')
    await click(w, 'Link Google')
    expect(w.find('dialog h2').text()).toBe('Link Google')
    await confirmPassword(w)
    expect(api.linkIdentity).toHaveBeenCalledWith('idp2', { password: 'pw' })
    expect(navigateTo).toHaveBeenCalledWith('https://accounts.google.example/auth?x=1')
  })

  it('never follows a non-web redirect', async () => {
    api.linkIdentity.mockResolvedValue({ redirect: 'javascript:alert(1)' })
    const w = await mountSection()
    await click(w, 'Link Google')
    await confirmPassword(w)
    expect(navigateTo).not.toHaveBeenCalled()
    expect(w.find('dialog [role=alert]').text()).toMatch(/invalid address/)
  })

  it('unlinks after re-auth and reloads the list', async () => {
    api.unlinkIdentity.mockResolvedValue(undefined)
    const w = await mountSection()
    api.identities.mockResolvedValue({ items: [], available: IDENTITIES.available })
    await click(w, 'Unlink')
    await confirmPassword(w)
    expect(api.unlinkIdentity).toHaveBeenCalledWith('li1', { password: 'pw' })
    expect(w.find('[role=status]').text()).toBe('Entra unlinked.')
    expect(w.text()).not.toContain('ann@contoso.com')
  })

  it("shows the server's reason when it is the last way to sign in", async () => {
    api.unlinkIdentity.mockRejectedValue(
      new ApiError(409, {
        error: 'conflict',
        error_description: 'This is your only way to sign in.',
      }),
    )
    const w = await mountSection()
    await click(w, 'Unlink')
    await confirmPassword(w)
    expect(w.find('dialog [role=alert]').text()).toBe('This is your only way to sign in.')
  })

  it('reports a finished link with the newest identity and strips the parameter', async () => {
    api.identities.mockResolvedValue({
      ...IDENTITIES,
      items: [
        ...IDENTITIES.items,
        {
          id: 'li2',
          idp_id: 'idp2',
          idp_name: 'Google',
          email: 'ann@gmail.example',
          linked_at: '2026-10-18T09:00:00Z',
          last_used_at: null,
        },
      ],
    })
    const w = await mountSection('/myaccount/security?federation=linked&keep=1')
    expect(w.find('[role=status]').text()).toBe('Linked Google (ann@gmail.example)')
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ keep: '1' })
  })

  it('explains a failed link, unknown codes as a plain failure', async () => {
    const known = await mountSection('/myaccount/security?federation_error=already_linked')
    expect(known.find('[role=alert]').text()).toMatch(/already linked to an account/)
    expect(router.currentRoute.value.query).toEqual({})
    known.unmount()

    const unknown = await mountSection('/myaccount/security?federation_error=weird')
    expect(unknown.find('[role=alert]').text()).toBe('Linking failed. Please try again.')
    unknown.unmount()

    const ended = await mountSection('/myaccount/security?federation_error=session_ended')
    expect(ended.find('[role=alert]').text()).toBe(
      'Your session ended before linking finished. Sign in again and retry.',
    )
  })

  it('names a linked identity without email by its provider only', async () => {
    const w = await mountSection('/myaccount/security?federation=linked')
    expect(w.find('[role=status]').text()).toBe('Linked Entra (ann@contoso.com)')
    api.identities.mockResolvedValue({
      items: IDENTITIES.items.map((i) => ({ ...i, email: null })),
      available: [],
    })
    w.unmount()
    const bare = await mountSection('/myaccount/security?federation=linked')
    expect(bare.find('[role=status]').text()).toBe('Linked Entra')
  })
})
