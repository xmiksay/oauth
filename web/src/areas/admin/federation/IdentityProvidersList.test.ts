import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import type { DirectoryRole } from '@/api/types'
import { fakeIdp, fakeMe } from '@/test/helpers'

const identityProviders = { list: vi.fn(), create: vi.fn() }
vi.mock('@/api/identityProviders', () => ({ identityProviders }))

const { default: IdentityProvidersList } = await import('./IdentityProvidersList.vue')
const { useAuthStore } = await import('@/stores/auth')

let router: Router

async function mountList(roles: DirectoryRole[]) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ directory_roles: roles }))
  router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/admin/identity-providers', component: IdentityProvidersList },
      {
        path: '/admin/identity-providers/:id',
        name: 'admin-identity-provider',
        component: IdentityProvidersList,
      },
    ],
  })
  await router.push('/admin/identity-providers')
  const w = mount(IdentityProvidersList, {
    global: { plugins: [pinia, router] },
    attachTo: document.body,
  })
  await flushPromises()
  return w
}

const button = (w: ReturnType<typeof mount>, text: string) =>
  w.findAll('button').find((b) => b.text() === text)

beforeEach(() => {
  document.body.innerHTML = ''
  identityProviders.list.mockReset().mockResolvedValue({
    items: [fakeIdp(), fakeIdp({ id: 'idp2', name: 'Okta', enabled: false, visible: false })],
    next_cursor: null,
  })
  identityProviders.create.mockReset()
})

describe('IdentityProvidersList', () => {
  it('lists providers with policy and status, read-only below Global Admin', async () => {
    const w = await mountList(['UserAdmin'])
    const rows = w.findAll('tbody tr').map((r) => r.text())
    expect(rows[0]).toContain('Entra')
    expect(rows[0]).toContain('Link existing accounts')
    expect(rows[0]).toContain('Enabled')
    expect(rows[1]).toContain('Disabled')
    expect(rows[1]).toContain('Hidden')
    expect(button(w, 'New identity provider')).toBeUndefined()
  })

  it('creates a provider with the typed secret and opens it', async () => {
    identityProviders.create.mockResolvedValue(fakeIdp({ id: 'new1' }))
    const w = await mountList(['GlobalAdmin'])
    await button(w, 'New identity provider')?.trigger('click')
    await w.find('#idp-name').setValue('Entra')
    await w.find('#idp-issuer').setValue('https://login.example.com/t/v2.0')
    await w.find('#idp-client-id').setValue('client-1')
    await w.find('#idp-secret').setValue('s3cret')
    await w.find('#idp-domains').setValue('contoso.com, fabrikam.com')
    await w.find('input[value=jit]').setValue(true)
    await w.find('#create-idp').trigger('submit')
    await flushPromises()
    expect(identityProviders.create).toHaveBeenCalledWith({
      name: 'Entra',
      issuer: 'https://login.example.com/t/v2.0',
      discovery_url: null,
      client_id: 'client-1',
      client_secret: 's3cret',
      client_auth: 'post',
      scopes: ['openid', 'email', 'profile'],
      policy: 'jit',
      trust_upstream_mfa: false,
      mfa_acr: null,
      email_domains: ['contoso.com', 'fabrikam.com'],
      enabled: true,
      visible: true,
    })
    expect(router.currentRoute.value.params.id).toBe('new1')
  })

  it('asks for the acr value only when trusting the provider MFA', async () => {
    const w = await mountList(['GlobalAdmin'])
    await button(w, 'New identity provider')?.trigger('click')
    expect(w.find('#idp-acr').exists()).toBe(false)
    expect(w.text()).toContain('Skip local MFA when the provider reports MFA')
    await w.find('#create-idp input[type=checkbox]').setValue(true)
    expect(w.find('#idp-acr').exists()).toBe(true)
  })
})
