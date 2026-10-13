import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import type { PageQuery, Paged, User } from '@/api/types'

const list = vi.fn<(q: PageQuery) => Promise<Paged<User>>>()
vi.mock('@/api/directory', () => ({
  users: { list: (q: PageQuery) => list(q) },
  groups: { list: vi.fn() },
}))
vi.mock('@/api/applications', () => ({ applications: { list: vi.fn() } }))

const { default: PrincipalPicker } = await import('./PrincipalPicker.vue')

const ann = { id: 'u1', email: 'ann@example.com', display_name: 'Ann' } as User

beforeEach(() => {
  vi.useFakeTimers()
  list.mockReset()
})
afterEach(() => vi.useRealTimers())

function picker() {
  return mount(PrincipalPicker, { props: { kind: 'user', label: 'User' } })
}

describe('PrincipalPicker', () => {
  it('searches after a pause and emits the picked principal', async () => {
    list.mockResolvedValue({ items: [ann], next_cursor: null })
    const w = picker()
    await w.find('input').setValue('an')
    vi.advanceTimersByTime(300)
    await flushPromises()
    expect(list).toHaveBeenCalledWith({ search: 'an', limit: 10 })
    await w.find('li button').trigger('click')
    expect(w.emitted('select')).toEqual([[{ id: 'u1', label: 'Ann', detail: 'ann@example.com' }]])
    expect(w.findAll('li')).toHaveLength(0)
  })

  it('says "No matches" only after a search finished empty', async () => {
    list.mockResolvedValue({ items: [], next_cursor: null })
    const w = picker()
    await w.find('input').setValue('zz')
    expect(w.text()).not.toContain('No matches')
    vi.advanceTimersByTime(300)
    await flushPromises()
    expect(w.text()).toContain('No matches.')
  })

  it('keeps the status region in the DOM and points aria-controls only at a rendered list', async () => {
    list.mockResolvedValue({ items: [ann], next_cursor: null })
    const w = picker()
    expect(w.find('[role=status]').exists()).toBe(true)
    expect(w.find('input').attributes('aria-controls')).toBeUndefined()
    await w.find('input').setValue('an')
    vi.advanceTimersByTime(300)
    await flushPromises()
    const listId = w.find('ul').attributes('id')
    expect(w.find('input').attributes('aria-controls')).toBe(listId)
  })

  it('clears a search error when the text changes', async () => {
    list.mockRejectedValueOnce(new TypeError('Failed to fetch'))
    const w = picker()
    await w.find('input').setValue('an')
    vi.advanceTimersByTime(300)
    await flushPromises()
    expect(w.find('[role=alert]').exists()).toBe(true)
    await w.find('input').setValue('')
    expect(w.find('[role=alert]').exists()).toBe(false)
  })

  it('drops a slow answer that arrives after the text was cleared', async () => {
    let release: (p: Paged<User>) => void = () => {}
    list.mockReturnValueOnce(new Promise((r) => (release = r)))
    const w = picker()
    await w.find('input').setValue('an')
    vi.advanceTimersByTime(300)
    await w.find('input').setValue('')
    release({ items: [ann], next_cursor: null })
    await flushPromises()
    expect(w.findAll('li')).toHaveLength(0)
    expect(w.text()).not.toContain('No matches')
  })
})
