import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { Application, ClientSecret } from '@/api/types'
import { fakeMe } from '@/test/helpers'

const applications = { get: vi.fn() }
const secrets = { list: vi.fn(), create: vi.fn(), remove: vi.fn() }
const settings = { get: vi.fn() }
vi.mock('@/api/applications', () => ({ applications, secrets }))
vi.mock('@/api/access', () => ({ settings }))

const { default: AppSecrets } = await import('./AppSecrets.vue')
const { useAuthStore } = await import('@/stores/auth')
const { useApplicationStore } = await import('@/stores/application')

const APP = {
  id: 'a1',
  client_id: 'infra',
  display_name: 'Infra',
  client_type: 'confidential',
  builtin: false,
} as Application

const NEVER: ClientSecret = {
  id: 's1',
  hint: 'abc',
  description: 'deploy',
  expires_at: null,
  never_expires: true,
  created_at: '',
}

async function mountPage(allowNever: boolean, items: ClientSecret[] = []) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ directory_roles: ['ApplicationAdmin'] }))
  applications.get.mockResolvedValue(APP)
  secrets.list.mockResolvedValue({ items })
  settings.get.mockResolvedValue({ allow_non_expiring_secrets: allowNever })
  await useApplicationStore().load(APP.id)
  const w = mount(AppSecrets, { global: { plugins: [pinia] } })
  await flushPromises()
  return w
}

const options = (w: Awaited<ReturnType<typeof mountPage>>) =>
  w.findAll('#as-days option').map((o) => o.text())

beforeEach(() => {
  ;[applications, secrets, settings].forEach((m) => Object.values(m).forEach((f) => f.mockReset()))
})

describe('AppSecrets', () => {
  it('offers "Never" only when the tenant allows it', async () => {
    expect(options(await mountPage(false))).not.toContain('Never')
    expect(options(await mountPage(true))).toContain('Never')
  })

  it('creates a non-expiring secret and shows its value once', async () => {
    const w = await mountPage(true)
    secrets.create.mockResolvedValue({ ...NEVER, secret: 'VALUE' })
    await w.find('#as-days').setValue('0')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(secrets.create).toHaveBeenCalledWith('a1', { never_expires: true })
    expect(w.findComponent({ name: 'SecretOnceDialog' }).props('values')).toEqual(['VALUE'])
  })

  it('sends a lifetime by default and lists a non-expiring secret as Never', async () => {
    const w = await mountPage(false, [NEVER])
    expect(w.find('tbody').text()).toContain('Never')
    secrets.create.mockResolvedValue({ ...NEVER, secret: 'VALUE' })
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(secrets.create).toHaveBeenCalledWith('a1', { expires_in_days: 180 })
  })
})
