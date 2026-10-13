<script setup lang="ts">
import { computed } from 'vue'
import ModalDialog from './ModalDialog.vue'
import CopyButton from './CopyButton.vue'

/**
 * Shows one-time secrets (passwords, client secrets, recovery codes). The values live only in
 * the caller's local state for as long as the dialog is open — never in a store or storage.
 */
const props = defineProps<{
  title: string
  /** `null` = closed. */
  values: string[] | null
  description?: string
  /** Offers a .txt download when set. */
  filename?: string
}>()
const emit = defineEmits<{ close: [] }>()

const text = computed(() => (props.values ?? []).join('\n'))

function download() {
  if (!props.filename) return
  const url = URL.createObjectURL(new Blob([`${text.value}\n`], { type: 'text/plain' }))
  const a = document.createElement('a')
  a.href = url
  a.download = props.filename
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <ModalDialog
    :open="values !== null"
    :title="title"
    @close="emit('close')"
  >
    <p
      v-if="description"
      class="muted text-sm"
    >
      {{ description }}
    </p>
    <div
      role="alert"
      class="mt-3 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
    >
      Copy this now. You won't be able to see it again after you close this dialog.
    </div>
    <ul
      class="mt-3 grid gap-1 rounded-md bg-neutral-100 p-3 dark:bg-neutral-800"
      :class="(values?.length ?? 0) > 1 ? 'sm:grid-cols-2' : ''"
      data-testid="secret-values"
    >
      <li
        v-for="(v, i) in values ?? []"
        :key="i"
        class="mono text-sm select-all"
      >
        {{ v }}
      </li>
    </ul>
    <template #actions>
      <CopyButton :text="text" />
      <button
        v-if="filename"
        type="button"
        class="btn"
        @click="download"
      >
        Download
      </button>
      <button
        type="button"
        class="btn btn-primary"
        @click="emit('close')"
      >
        Done
      </button>
    </template>
  </ModalDialog>
</template>
