import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import type { IdpGroupMapping } from '@/api/types'

const identityProviders = { mappings: vi.fn(), addMapping: vi.fn(), removeMapping: vi.fn() }
vi.mock('@/api/identityProviders', () => ({ identityProviders }))
const groupsList = vi.fn()
vi.mock('@/api/directory', () => ({ users: { list: vi.fn() }, groups: { list: groupsList } }))
vi.mock('@/api/applications', () => ({ applications: { list: vi.fn() } }))

const { default: GroupMappings } = await import('./GroupMappings.vue')

const mapping: IdpGroupMapping = {
  id: 'm1',
  idp_id: 'idp1',
  claim: 'groups',
  value: 'eng',
  group_id: 'g1',
  group_display_name: 'Engineering',
  created_at: '2026-11-22T10:00:00Z',
}

async function mountIt(canWrite = true, openToAnyTenant = false) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/g/:id', name: 'admin-group', component: { template: '<div />' } }],
  })
  const w = mount(GroupMappings, {
    props: { idpId: 'idp1', canWrite, openToAnyTenant },
    global: { plugins: [router] },
    attachTo: document.body,
  })
  await flushPromises()
  return w
}

beforeEach(() => {
  document.body.innerHTML = ''
  vi.useFakeTimers()
  Object.values(identityProviders).forEach((f) => f.mockReset())
  groupsList.mockReset()
  identityProviders.mappings.mockResolvedValue({ items: [mapping], next_cursor: null })
})
afterEach(() => vi.useRealTimers())

describe('GroupMappings', () => {
  it('has a claim pattern the browser compiles (the `v` flag)', async () => {
    const w = await mountIt()
    const pattern = w.find('input[pattern]').attributes('pattern') ?? ''
    const re = new RegExp(`^(?:${pattern})$`, 'v')
    expect(re.test('groups')).toBe(true)
    expect(re.test('https://example.com/claims/roles')).toBe(true)
    expect(re.test('bad claim')).toBe(false)
  })

  it('lists mappings with their group', async () => {
    const w = await mountIt()
    expect(identityProviders.mappings).toHaveBeenCalledWith('idp1', expect.anything())
    const row = w.find('tbody tr')
    expect(row.text()).toContain('groups')
    expect(row.text()).toContain('eng')
    expect(row.text()).toContain('Engineering')
  })

  it('adds a mapping to a picked group, then reloads', async () => {
    groupsList.mockResolvedValue({
      items: [{ id: 'g2', display_name: 'Ops', description: null }],
      next_cursor: null,
    })
    identityProviders.addMapping.mockResolvedValue({ ...mapping, id: 'm2' })
    const w = await mountIt()
    expect(w.find('button[type=submit]').attributes('disabled')).toBeDefined()
    await w.find('#gm-claim').setValue(' roles ')
    await w.find('#gm-value').setValue('ops')
    const search = w.findAll('input').find((i) => !['gm-claim', 'gm-value'].includes(i.attributes('id') ?? ''))
    await search?.setValue('op')
    vi.advanceTimersByTime(300)
    await flushPromises()
    await w.find('li button').trigger('click')
    expect(w.find('[data-testid=picked-group]').text()).toContain('Ops')
    await w.find('[data-testid=add-mapping]').trigger('submit')
    await flushPromises()
    expect(identityProviders.addMapping).toHaveBeenCalledWith('idp1', {
      claim: 'roles',
      value: 'ops',
      group_id: 'g2',
    })
    expect(identityProviders.mappings).toHaveBeenCalledTimes(2)
    expect((w.find('#gm-value').element as HTMLInputElement).value).toBe('')
  })

  it('removes a mapping after confirming', async () => {
    identityProviders.removeMapping.mockResolvedValue(undefined)
    const w = await mountIt()
    await w.findAll('button').find((b) => b.text() === 'Remove')?.trigger('click')
    const confirm = w.findAll('dialog button').filter((b) => b.text() === 'Remove')
    await confirm[0]?.trigger('click')
    await flushPromises()
    expect(identityProviders.removeMapping).toHaveBeenCalledWith('idp1', 'm1')
  })

  it('is read-only without write access', async () => {
    const w = await mountIt(false)
    expect(w.find('[data-testid=add-mapping]').exists()).toBe(false)
    expect(w.findAll('button').filter((b) => b.text() === 'Remove')).toHaveLength(0)
  })

  it('explains instead of offering a mapping on an Entra provider open to every tenant', async () => {
    const w = await mountIt(true, true)
    expect(w.find('[data-testid=add-mapping]').exists()).toBe(false)
    expect(w.find('[data-testid=needs-allowed-tenants]').text()).toContain('allowed tenants')
    expect(w.findAll('button').filter((b) => b.text() === 'Remove')).toHaveLength(1)
  })
})
