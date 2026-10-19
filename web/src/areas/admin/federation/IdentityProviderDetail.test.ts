import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import type { DirectoryRole } from '@/api/types'
import { fakeIdp, fakeMe } from '@/test/helpers'

const identityProviders = { get: vi.fn(), update: vi.fn(), remove: vi.fn() }
vi.mock('@/api/identityProviders', () => ({ identityProviders }))

const { default: IdentityProviderDetail } = await import('./IdentityProviderDetail.vue')
const { useAuthStore } = await import('@/stores/auth')

async function mountPage(roles: DirectoryRole[] = ['GlobalAdmin']) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ directory_roles: roles }))
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      {
        path: '/admin/identity-providers',
        name: 'admin-identity-providers',
        component: IdentityProviderDetail,
      },
      { path: '/admin/identity-providers/:id', component: IdentityProviderDetail },
    ],
  })
  await router.push('/admin/identity-providers/idp1')
  const w = mount(IdentityProviderDetail, {
    global: { plugins: [pinia, router] },
    attachTo: document.body,
  })
  await flushPromises()
  return w
}

const buttons = (w: ReturnType<typeof mount>, text: string) =>
  w.findAll('button').filter((b) => b.text() === text)

const LOCKOUT =
  '2 users can sign in only through this provider. They will be locked out until an administrator resets their password or sends an invitation.'

beforeEach(() => {
  document.body.innerHTML = ''
  Object.values(identityProviders).forEach((f) => f.mockReset())
  identityProviders.get.mockResolvedValue(fakeIdp())
})

describe('IdentityProviderDetail', () => {
  it('shows the redirect URI to register and whether a secret is set, never a secret', async () => {
    const w = await mountPage()
    expect(w.find('[data-testid=redirect-uri]').text()).toBe(
      'https://contoso.auth.example/federation/callback',
    )
    expect(w.text()).toContain('Register this redirect URI at the identity provider')
    expect(w.text()).toContain('Secret set')
    expect((w.find('#idp-secret').element as HTMLInputElement).value).toBe('')

    identityProviders.get.mockResolvedValue(fakeIdp({ has_secret: false }))
    const none = await mountPage()
    expect(none.text()).toContain('No secret')
    expect(none.text()).not.toContain('Remove the secret')
  })

  it('is read-only below Global Admin', async () => {
    const w = await mountPage(['UserAdmin'])
    for (const label of ['Save', 'Disable', 'Delete']) expect(buttons(w, label)).toHaveLength(0)
    expect(w.find('#idp-secret').exists()).toBe(false)
    expect(w.find('fieldset').attributes('disabled')).toBeDefined()
  })

  it('patches only changed fields plus a new secret, then clears the secret', async () => {
    identityProviders.update.mockResolvedValue(
      fakeIdp({ email_domains: ['fabrikam.com'], updated_at: '2026-10-02T10:00:00Z' }),
    )
    const w = await mountPage()
    await w.find('#idp-domains').setValue('fabrikam.com')
    await w.find('#idp-secret').setValue('n3w')
    await w.find('#edit-idp').trigger('submit')
    await flushPromises()
    expect(identityProviders.update).toHaveBeenCalledWith('idp1', {
      email_domains: ['fabrikam.com'],
      client_secret: 'n3w',
    })
    expect((w.find('#idp-secret').element as HTMLInputElement).value).toBe('')
    expect(w.find('[role=status]').text()).toBe('Saved.')
  })

  it('removes the secret with null', async () => {
    identityProviders.update.mockResolvedValue(fakeIdp({ has_secret: false }))
    const w = await mountPage()
    const remove = w.findAll('label').find((l) => l.text() === 'Remove the secret')
    await remove?.find('input').setValue(true)
    await w.find('#edit-idp').trigger('submit')
    await flushPromises()
    expect(identityProviders.update).toHaveBeenCalledWith('idp1', { client_secret: null })
  })

  it('sends nothing when nothing changed', async () => {
    const w = await mountPage()
    await w.find('#edit-idp').trigger('submit')
    await flushPromises()
    expect(identityProviders.update).not.toHaveBeenCalled()
  })

  it('warns about users it would lock out, before disabling and deleting too', async () => {
    identityProviders.get.mockResolvedValue(fakeIdp({ users_only_via: 2 }))
    identityProviders.update.mockResolvedValue(fakeIdp({ enabled: false, users_only_via: 2 }))
    const w = await mountPage()
    expect(w.find('[data-testid=lockout]').text()).toBe(LOCKOUT)

    await buttons(w, 'Delete')[0]?.trigger('click')
    expect(w.findAll('dialog p').map((p) => p.text())).toContain(
      `Entra and all identities linked to it are deleted. ${LOCKOUT}`,
    )
    await buttons(w, 'Cancel')[0]?.trigger('click')

    await buttons(w, 'Disable')[0]?.trigger('click')
    expect(w.text()).toContain(`Users can no longer sign in with Entra. ${LOCKOUT}`)
    await buttons(w, 'Disable')[1]?.trigger('click')
    await flushPromises()
    expect(identityProviders.update).toHaveBeenCalledWith('idp1', { enabled: false })
    expect(buttons(w, 'Enable')).toHaveLength(1)
  })

  it('confirms before an issuer change unlinks every linked user', async () => {
    identityProviders.get.mockResolvedValue(fakeIdp({ linked_users: 3 }))
    identityProviders.update.mockResolvedValue(fakeIdp({ issuer: 'https://new.example' }))
    const w = await mountPage()
    expect(w.find('[data-testid=linked-users]').text()).toBe('3')
    await w.find('#idp-issuer').setValue('https://new.example')
    await w.find('#edit-idp').trigger('submit')
    await flushPromises()
    expect(identityProviders.update).not.toHaveBeenCalled()
    expect(w.text()).toContain(
      'Changing the issuer, client ID or discovery URL unlinks all 3 linked users; they must link again.',
    )
    await buttons(w, 'Cancel')[0]?.trigger('click')
    expect(identityProviders.update).not.toHaveBeenCalled()

    await w.find('#edit-idp').trigger('submit')
    await flushPromises()
    await buttons(w, 'Save and unlink')[0]?.trigger('click')
    await flushPromises()
    expect(identityProviders.update).toHaveBeenCalledWith('idp1', {
      issuer: 'https://new.example',
    })
  })

  it('saves other changes without asking, and identity changes when nobody is linked', async () => {
    identityProviders.get.mockResolvedValue(fakeIdp({ linked_users: 3 }))
    identityProviders.update.mockResolvedValue(fakeIdp({ linked_users: 3 }))
    const w = await mountPage()
    await w.find('#idp-name').setValue('Entra ID')
    await w.find('#edit-idp').trigger('submit')
    await flushPromises()
    expect(identityProviders.update).toHaveBeenCalledWith('idp1', { name: 'Entra ID' })

    identityProviders.get.mockResolvedValue(fakeIdp())
    const none = await mountPage()
    await none.find('#idp-client-id').setValue('client-2')
    await none.find('#edit-idp').trigger('submit')
    await flushPromises()
    expect(identityProviders.update).toHaveBeenLastCalledWith('idp1', { client_id: 'client-2' })
  })

  it('says nothing about lockouts when no user depends on it', async () => {
    const w = await mountPage()
    expect(w.find('[data-testid=lockout]').exists()).toBe(false)
    await buttons(w, 'Disable')[0]?.trigger('click')
    expect(w.text()).not.toContain('locked out')
  })
})
