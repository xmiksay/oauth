import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { CreatedUser, UserCreate } from '@/api/directory'
import type { User } from '@/api/types'

const create = vi.fn<(body: UserCreate) => Promise<CreatedUser>>()
vi.mock('@/api/directory', () => ({ users: { create: (b: UserCreate) => create(b) } }))

const { default: CreateUserDialog } = await import('./CreateUserDialog.vue')
const { useAuthStore } = await import('@/stores/auth')

const created: User = {
  id: 'u1',
  email: 'new@example.com',
  display_name: 'New',
  user_type: 'member',
  email_verified: false,
  disabled: false,
  must_change_password: false,
  has_password: false,
  created_at: '',
  updated_at: '',
}

function mountDialog(email: boolean) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe({
    ...created,
    id: 'admin',
    directory_roles: ['UserAdmin'],
    mfa: { totp: false, totp_pending: false, recovery_codes_remaining: 0 },
    features: { email },
  })
  return mount(CreateUserDialog, { props: { open: true }, global: { plugins: [pinia] } })
}

async function fillBasics(w: ReturnType<typeof mountDialog>) {
  await flushPromises()
  await w.find('#cu-email').setValue(' new@example.com ')
  await w.find('#cu-name').setValue('New')
}

beforeEach(() => create.mockReset())

describe('CreateUserDialog', () => {
  it('offers no invitation when the server cannot send email', async () => {
    const w = mountDialog(false)
    await flushPromises()
    expect(w.find('[data-testid=cu-invite]').exists()).toBe(false)
    expect(w.text()).toContain('Set the password myself')
  })

  it('sends invite: true without any password and emits the result', async () => {
    const res = { user: created, one_time_password: null, invite_sent: true }
    create.mockResolvedValue(res)
    const w = mountDialog(true)
    await fillBasics(w)
    // A password typed first must not leak into the invite request.
    await w.find('input[type=checkbox]:not([data-testid])').setValue(true)
    await w.find('#cu-password').setValue('a-long-password-1')
    await w.find('[data-testid=cu-invite]').setValue(true)
    expect(w.find('#cu-password').exists()).toBe(false)
    expect(w.text()).not.toContain('Set the password myself')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(create).toHaveBeenCalledWith({
      email: 'new@example.com',
      display_name: 'New',
      invite: true,
    })
    expect(w.emitted('created')).toEqual([[res]])
  })

  it('keeps the generated-password flow without the invite box ticked', async () => {
    create.mockResolvedValue({ user: created, one_time_password: 'otp', invite_sent: false })
    const w = mountDialog(true)
    await fillBasics(w)
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(create).toHaveBeenCalledWith({ email: 'new@example.com', display_name: 'New' })
  })
})
