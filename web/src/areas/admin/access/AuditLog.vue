<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { auditEvents } from '@/api/access'
import type { AuditEvent } from '@/api/types'
import { usePagedList } from '@/composables/usePagedList'
import { formatDate } from '@/lib/format'
import PageHeader from '@/components/PageHeader.vue'
import ListShell from '@/components/ListShell.vue'
import ModalDialog from '@/components/ModalDialog.vue'
import { AUDIT_EVENT_TYPES, localToIso } from './eventTypes'

const filters = reactive({ event_type: '', actor_id: '', target_id: '', from: '', to: '' })
// Filters apply on submit so typing an id doesn't fire a request per keystroke.
const applied = ref({ ...filters })

const list = usePagedList<AuditEvent>((q) =>
  auditEvents.list({
    ...q,
    event_type: applied.value.event_type || undefined,
    actor_id: applied.value.actor_id.trim() || undefined,
    target_id: applied.value.target_id.trim() || undefined,
    from: localToIso(applied.value.from),
    to: localToIso(applied.value.to),
  }),
)

function apply() {
  applied.value = { ...filters }
  list.reload()
}

function clear() {
  Object.assign(filters, { event_type: '', actor_id: '', target_id: '', from: '', to: '' })
  apply()
}

const selected = ref<AuditEvent | null>(null)
const json = computed(() => (selected.value ? JSON.stringify(selected.value, null, 2) : ''))
</script>

<template>
  <section>
    <PageHeader
      title="Audit log"
      description="Changes and sign-ins in this directory, newest first."
    />
    <form
      class="card mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5 lg:items-end"
      @submit.prevent="apply"
    >
      <div>
        <label
          class="label"
          for="al-type"
        >Activity</label>
        <select
          id="al-type"
          v-model="filters.event_type"
          class="input"
        >
          <option value="">
            All
          </option>
          <option
            v-for="t in AUDIT_EVENT_TYPES"
            :key="t"
            :value="t"
          >
            {{ t }}
          </option>
        </select>
      </div>
      <div>
        <label
          class="label"
          for="al-actor"
        >Actor ID</label>
        <input
          id="al-actor"
          v-model="filters.actor_id"
          class="input font-mono"
        >
      </div>
      <div>
        <label
          class="label"
          for="al-target"
        >Target ID</label>
        <input
          id="al-target"
          v-model="filters.target_id"
          class="input font-mono"
        >
      </div>
      <div>
        <label
          class="label"
          for="al-from"
        >From</label>
        <input
          id="al-from"
          v-model="filters.from"
          class="input"
          type="datetime-local"
        >
      </div>
      <div>
        <label
          class="label"
          for="al-to"
        >To (exclusive)</label>
        <input
          id="al-to"
          v-model="filters.to"
          class="input"
          type="datetime-local"
        >
      </div>
      <div class="flex gap-2 lg:col-span-5">
        <button
          type="submit"
          class="btn btn-primary"
        >
          Apply
        </button>
        <button
          type="button"
          class="btn"
          @click="clear"
        >
          Clear
        </button>
      </div>
    </form>
    <ListShell
      :list="list"
      empty="No events match."
    >
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              Date
            </th>
            <th scope="col">
              Activity
            </th>
            <th scope="col">
              Result
            </th>
            <th
              scope="col"
              class="hidden md:table-cell"
            >
              Actor
            </th>
            <th
              scope="col"
              class="hidden lg:table-cell"
            >
              Target
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="e in list.items"
            :key="e.id"
          >
            <td class="whitespace-nowrap">
              <button
                type="button"
                class="btn-link"
                @click="selected = e"
              >
                {{ formatDate(e.at) }}
              </button>
            </td>
            <td class="mono">
              {{ e.event_type }}
            </td>
            <td>
              <span :class="e.outcome === 'failure' ? 'text-red-700 dark:text-red-400' : ''">{{
                e.outcome
              }}</span>
            </td>
            <td class="hidden md:table-cell">
              {{ e.actor_type }} <span class="mono muted">{{ e.actor_id }}</span>
            </td>
            <td class="hidden lg:table-cell">
              {{ e.target_type }} <span class="mono muted">{{ e.target_id }}</span>
            </td>
          </tr>
        </tbody>
      </table>
    </ListShell>
    <ModalDialog
      :open="selected !== null"
      title="Audit event"
      wide
      @close="selected = null"
    >
      <pre
        class="max-h-[60vh] overflow-auto rounded-md bg-neutral-100 p-3 text-xs dark:bg-neutral-800"
      >{{ json }}</pre>
      <template #actions>
        <button
          type="button"
          class="btn"
          @click="selected = null"
        >
          Close
        </button>
      </template>
    </ModalDialog>
  </section>
</template>
