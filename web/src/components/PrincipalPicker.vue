<script setup lang="ts">
import { ref, useId, watch } from 'vue'
import { users, groups } from '@/api/directory'
import { applications } from '@/api/applications'
import type { PrincipalType } from '@/api/types'
import { SEARCH_DEBOUNCE_MS } from '@/composables/usePagedList'
import ErrorAlert from './ErrorAlert.vue'

export interface Picked {
  id: string
  label: string
  detail: string
}

/** Search-as-you-type picker for a user, group or application. */
const props = defineProps<{ kind: PrincipalType; label: string }>()
const emit = defineEmits<{ select: [picked: Picked] }>()

const text = ref('')
const results = ref<Picked[]>([])
const error = ref<unknown>(null)
/** A search for the current text finished (distinguishes "no matches" from "not yet"). */
const searched = ref(false)
const inputId = useId()
const listId = useId()
let timer: ReturnType<typeof setTimeout> | undefined
let seq = 0

async function search(q: string): Promise<Picked[]> {
  const query = { search: q, limit: 10 }
  switch (props.kind) {
    case 'user':
      return (await users.list(query)).items.map((u) => ({
        id: u.id,
        label: u.display_name || u.email,
        detail: u.email,
      }))
    case 'group':
      return (await groups.list(query)).items.map((g) => ({
        id: g.id,
        label: g.display_name,
        detail: g.description ?? '',
      }))
    case 'application':
      return (await applications.list(query)).items.map((a) => ({
        id: a.id,
        label: a.display_name,
        detail: a.client_id,
      }))
  }
}

/** Drops pending and in-flight searches (their late answers must not reappear). */
function reset() {
  clearTimeout(timer)
  seq++
  results.value = []
  searched.value = false
  error.value = null
}

watch([text, () => props.kind], () => {
  reset()
  const q = text.value.trim()
  if (!q) return
  timer = setTimeout(async () => {
    const mine = ++seq
    try {
      const found = await search(q)
      if (mine === seq) {
        results.value = found
        searched.value = true
        error.value = null
      }
    } catch (err) {
      if (mine === seq) error.value = err
    }
  }, SEARCH_DEBOUNCE_MS)
})

function pick(p: Picked) {
  emit('select', p)
  text.value = ''
  reset()
}
</script>

<template>
  <div>
    <label
      class="label"
      :for="inputId"
    >{{ label }}</label>
    <input
      :id="inputId"
      v-model="text"
      class="input"
      type="search"
      autocomplete="off"
      :aria-controls="results.length ? listId : undefined"
      placeholder="Type to search…"
    >
    <ul
      v-if="results.length"
      :id="listId"
      class="mt-1 max-h-56 overflow-y-auto rounded-md border border-neutral-200 dark:border-neutral-700"
    >
      <li
        v-for="r in results"
        :key="r.id"
      >
        <button
          type="button"
          class="block w-full px-3 py-1.5 text-left text-sm hover:bg-neutral-100 focus-visible:bg-neutral-100 focus-visible:outline-none dark:hover:bg-neutral-800 dark:focus-visible:bg-neutral-800"
          @click="pick(r)"
        >
          {{ r.label }} <span class="muted text-xs">{{ r.detail }}</span>
        </button>
      </li>
    </ul>
    <!-- Always present so the "No matches" change is announced. -->
    <p
      class="muted mt-1 text-sm"
      role="status"
      aria-live="polite"
    >
      {{ searched && !results.length ? 'No matches.' : '' }}
    </p>
    <ErrorAlert
      class="mt-1"
      :error="error"
    />
  </div>
</template>
