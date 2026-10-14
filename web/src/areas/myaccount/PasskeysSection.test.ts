import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { ApiError } from '@/api/client'
import {
  CREATION_OPTIONS,
  REGISTRATION_JSON,
  domError,
  fakeMe,
  fakePasskey,
  stubWebAuthn,
} from '@/test/helpers'

const api = {
  passkeys: vi.fn(),
  passkeyOptions: vi.fn(),
  addPasskey: vi.fn(),
  renamePasskey: vi.fn(),
  removePasskey: vi.fn(),
  reauthOptions: vi.fn(),
}
vi.mock('@/api/me', () => ({ me: api }))

const { default: PasskeysSection } = await import('./PasskeysSection.vue')
const { useAuthStore } = await import('@/stores/auth')

async function mountSection() {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe())
  const w = mount(PasskeysSection, { global: { plugins: [pinia] }, attachTo: document.body })
  await flushPromises()
  return w
}

const button = (w: ReturnType<typeof mount>, text: string) =>
  w.findAll('button').find((b) => b.text() === text)

async function click(w: ReturnType<typeof mount>, text: string) {
  await button(w, text)?.trigger('click')
  await flushPromises()
}

async function confirmPassword(w: ReturnType<typeof mount>) {
  await w.find('#pp-password').setValue('pw')
  await w.find('#reauth-prompt').trigger('submit')
  await flushPromises()
}

const laptop = fakePasskey()
const key = fakePasskey({
  id: 'pk2',
  name: 'YubiKey',
  backup_state: false,
  last_used_at: '2026-10-10T10:00:00Z',
})

beforeEach(() => {
  Object.values(api).forEach((f) => f.mockReset())
  api.passkeys.mockResolvedValue({ items: [laptop, key] })
})
afterEach(() => {
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})

describe('PasskeysSection', () => {
  it('lists passkeys as synced or device-bound with their last use', async () => {
    const w = await mountSection()
    const rows = w.findAll('tbody tr').map((r) => r.text())
    expect(rows[0]).toContain('Laptop')
    expect(rows[0]).toContain('Synced')
    expect(rows[0]).toContain('Never')
    expect(rows[1]).toContain('Device-bound')
    expect(w.text()).toContain("This browser can't create passkeys.")
  })

  it('adds a passkey: re-auth, then a create click with an optional name', async () => {
    const { create } = stubWebAuthn()
    api.passkeyOptions.mockResolvedValue(CREATION_OPTIONS)
    api.addPasskey.mockResolvedValue(fakePasskey({ id: 'pk3', name: 'Phone' }))
    const w = await mountSection()
    await click(w, 'Add a passkey')
    await confirmPassword(w)
    expect(api.passkeyOptions).toHaveBeenCalledWith({ password: 'pw' })
    expect(create).not.toHaveBeenCalled()

    await w.find('#ap-name').setValue(' Phone ')
    await w.find('#add-passkey').trigger('submit')
    await flushPromises()
    expect(api.addPasskey).toHaveBeenCalledWith(REGISTRATION_JSON, 'Phone')
    expect(w.find('[role=status]').text()).toBe('Passkey "Phone" added.')
    expect(w.emitted('changed')).toHaveLength(1)
    expect(api.passkeys).toHaveBeenCalledTimes(2)
  })

  it('keeps the create dialog open only on a dismissal; a rejection closes it', async () => {
    const { create } = stubWebAuthn()
    api.passkeyOptions.mockResolvedValue(CREATION_OPTIONS)
    api.addPasskey.mockRejectedValue(new ApiError(409, { error: 'conflict' }))
    create.mockRejectedValueOnce(domError('NotAllowedError'))
    const w = await mountSection()
    await click(w, 'Add a passkey')
    await confirmPassword(w)
    await w.find('#add-passkey').trigger('submit')
    await flushPromises()
    expect(w.find('[role=alert]').exists()).toBe(false)
    expect(w.text()).toContain('The passkey request was cancelled.')
    expect(w.find('#add-passkey').exists()).toBe(true)

    // The server consumed the challenge: retrying these options would only orphan another
    // credential on the authenticator, so the dialog goes and the user starts over.
    await w.find('#add-passkey').trigger('submit')
    await flushPromises()
    expect(api.addPasskey).toHaveBeenCalledWith(REGISTRATION_JSON, undefined)
    expect(w.find('#add-passkey').exists()).toBe(false)
    expect(w.find('[role=alert]').text()).toMatch(/already registered, or you have reached/)
    expect(w.emitted('changed')).toBeUndefined()
    await click(w, 'Add a passkey')
    expect(w.find('[role=alert]').exists()).toBe(false)
    await confirmPassword(w)
    expect(api.passkeyOptions).toHaveBeenCalledTimes(2)
  })

  it('explains the passkey cap at the re-auth step', async () => {
    stubWebAuthn()
    api.passkeyOptions.mockRejectedValue(new ApiError(409, { error: 'conflict' }))
    const w = await mountSection()
    await click(w, 'Add a passkey')
    await confirmPassword(w)
    expect(w.text()).toContain('You have reached the maximum of 20 passkeys.')
    expect(w.find('#add-passkey').exists()).toBe(false)
  })

  it('renames inline', async () => {
    api.renamePasskey.mockResolvedValue({ ...laptop, name: 'Work laptop' })
    const w = await mountSection()
    await click(w, 'Rename')
    await w.find('#pk-name-pk1').setValue('Work laptop')
    await w.find('tbody form').trigger('submit')
    await flushPromises()
    expect(api.renamePasskey).toHaveBeenCalledWith('pk1', 'Work laptop')
    expect(w.find('tbody tr').text()).toContain('Work laptop')
    expect(w.find('#pk-name-pk1').exists()).toBe(false)
  })

  it('rejects an empty name without a request', async () => {
    const w = await mountSection()
    await click(w, 'Rename')
    await w.find('#pk-name-pk1').setValue('  ')
    await w.find('tbody form').trigger('submit')
    await flushPromises()
    expect(api.renamePasskey).not.toHaveBeenCalled()
    expect(w.find('[role=alert]').text()).toMatch(/1 to 64 characters/)
  })

  it('removes after re-auth and explains the last sign-in method', async () => {
    api.removePasskey
      .mockRejectedValueOnce(new ApiError(409, { error: 'conflict' }))
      .mockResolvedValueOnce(undefined)
    const w = await mountSection()
    await click(w, 'Remove')
    await confirmPassword(w)
    expect(api.removePasskey).toHaveBeenCalledWith('pk1', { password: 'pw' })
    expect(w.find('[role=alert]').text()).toMatch(/only way to sign in/)

    await confirmPassword(w)
    expect(w.find('[role=status]').text()).toBe('Passkey "Laptop" removed.')
    expect(w.emitted('changed')).toHaveLength(1)
  })
})
