import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import { usePagedList, SEARCH_DEBOUNCE_MS } from './usePagedList'
import type { PageQuery, Paged } from '@/api/types'

function pages(...ps: Paged<number>[]) {
  return vi.fn<(q: PageQuery) => Promise<Paged<number>>>(async () => {
    const p = ps.shift()
    if (!p) throw new Error('no more pages')
    return p
  })
}

beforeEach(() => vi.useFakeTimers())
afterEach(() => vi.useRealTimers())

describe('usePagedList', () => {
  it('walks forward with next_cursor and back through the cursor stack', async () => {
    const fetch = pages(
      { items: [1, 2], next_cursor: 'c2' },
      { items: [3], next_cursor: null },
      { items: [1, 2], next_cursor: 'c2' },
    )
    const list = usePagedList(fetch, 2)
    await list.load()
    expect([list.items, list.page, list.hasPrev, list.hasNext]).toEqual([[1, 2], 1, false, true])
    await list.next()
    expect([list.items, list.page, list.hasPrev, list.hasNext]).toEqual([[3], 2, true, false])
    expect(fetch.mock.calls[1]?.[0]).toMatchObject({ limit: 2, cursor: 'c2' })
    await list.prev()
    expect(fetch.mock.calls[2]?.[0]).toMatchObject({ cursor: null })
    expect(list.page).toBe(1)
  })

  it('debounces search and restarts from the first page', async () => {
    const fetch = pages(
      { items: [1], next_cursor: 'c2' },
      { items: [2], next_cursor: null },
      { items: [9], next_cursor: null },
    )
    const list = usePagedList(fetch)
    await list.load()
    await list.next()
    list.setSearch('a')
    list.setSearch('an')
    await nextTick()
    vi.advanceTimersByTime(SEARCH_DEBOUNCE_MS)
    await vi.waitFor(() => expect(list.items).toEqual([9]))
    expect(fetch).toHaveBeenCalledTimes(3)
    expect(fetch.mock.calls[2]?.[0]).toMatchObject({ cursor: null, search: 'an' })
    expect(list.page).toBe(1)
  })

  it('keeps the error and clears items on failure', async () => {
    const list = usePagedList(pages())
    await list.load()
    expect(list.error).toBeInstanceOf(Error)
    expect(list.items).toEqual([])
    expect(list.loading).toBe(false)
  })

  it('ignores a stale response that finishes after a newer one', async () => {
    let release: (p: Paged<number>) => void = () => {}
    const slow = new Promise<Paged<number>>((r) => (release = r))
    const fetch = vi
      .fn<(q: PageQuery) => Promise<Paged<number>>>()
      .mockReturnValueOnce(slow)
      .mockResolvedValueOnce({ items: [2], next_cursor: null })
    const list = usePagedList(fetch)
    const first = list.load()
    await list.load()
    release({ items: [1], next_cursor: null })
    await first
    expect(list.items).toEqual([2])
  })
})
