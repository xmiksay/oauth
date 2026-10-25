import { computed, getCurrentScope, onScopeDispose, reactive, ref, shallowRef, watch, type Ref } from 'vue'
import type { PageQuery, Paged } from '@/api/types'

export const SEARCH_DEBOUNCE_MS = 300

/**
 * Cursor paging over a `{ items, next_cursor }` endpoint. The server only hands out forward
 * cursors, so earlier pages are revisited through the stack of cursors already used.
 */
export function usePagedList<T>(fetchPage: (q: PageQuery) => Promise<Paged<T>>, limit = 25) {
  const items = shallowRef<T[]>([]) as Ref<T[]>
  const loading = ref(false)
  const error = ref<unknown>(null)
  const search = ref('')
  const cursors = ref<(string | null)[]>([null])
  const nextCursor = ref<string | null>(null)
  let seq = 0
  let debounce: ReturnType<typeof setTimeout> | undefined

  const page = computed(() => cursors.value.length)
  const hasPrev = computed(() => cursors.value.length > 1)
  const hasNext = computed(() => nextCursor.value !== null)

  async function load() {
    const mine = ++seq
    loading.value = true
    error.value = null
    try {
      const res = await fetchPage({
        limit,
        cursor: cursors.value[cursors.value.length - 1] ?? null,
        search: search.value.trim() || undefined,
      })
      if (mine !== seq) return // a newer request (e.g. typing in search) superseded this one
      items.value = res.items
      nextCursor.value = res.next_cursor
    } catch (err) {
      if (mine !== seq) return
      error.value = err
      items.value = []
      nextCursor.value = null
    } finally {
      if (mine === seq) loading.value = false
    }
  }

  // Paging while a search change waits would pair the old search's cursor with the new search.
  function takePendingSearch() {
    if (debounce === undefined) return false
    clearTimeout(debounce)
    debounce = undefined
    return true
  }

  async function next() {
    if (nextCursor.value === null) return
    if (takePendingSearch()) return reload()
    cursors.value = [...cursors.value, nextCursor.value]
    await load()
  }

  async function prev() {
    if (cursors.value.length <= 1) return
    if (takePendingSearch()) return reload()
    cursors.value = cursors.value.slice(0, -1)
    await load()
  }

  /** Back to the first page (after a search change or a create / delete). */
  async function reload() {
    cursors.value = [null]
    await load()
  }

  function setSearch(text: string) {
    search.value = text
  }

  // Sync: a next() right after a search change must already see the pending debounce.
  watch(
    search,
    () => {
      clearTimeout(debounce)
      debounce = setTimeout(() => {
        debounce = undefined
        void reload()
      }, SEARCH_DEBOUNCE_MS)
    },
    { flush: 'sync' },
  )
  if (getCurrentScope()) onScopeDispose(() => clearTimeout(debounce))

  // reactive() so templates and props can read `list.items` without `.value`.
  return reactive({ items, loading, error, search, page, hasPrev, hasNext, load, next, prev, reload, setSearch })
}

export type PagedList<T> = ReturnType<typeof usePagedList<T>>
