<script setup lang="ts">
import { ref } from 'vue'
import ModalDialog from './ModalDialog.vue'
import ErrorAlert from './ErrorAlert.vue'

/** A button that asks for confirmation, then runs `action`; errors are shown in the dialog. */
const props = defineProps<{
  label: string
  title: string
  message: string
  confirmLabel?: string
  danger?: boolean
  disabled?: boolean
  action: () => Promise<unknown>
}>()
const emit = defineEmits<{ done: [] }>()

const open = ref(false)
const busy = ref(false)
const error = ref<unknown>(null)

function show() {
  error.value = null
  open.value = true
}

async function confirm() {
  busy.value = true
  error.value = null
  try {
    await props.action()
    open.value = false
    emit('done')
  } catch (err) {
    error.value = err
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <button
    type="button"
    class="btn"
    :class="{ 'text-red-700 dark:text-red-400': danger }"
    :disabled="disabled"
    @click="show"
  >
    {{ label }}
  </button>
  <ModalDialog
    :open="open"
    :title="title"
    @close="busy || (open = false)"
  >
    <p class="text-sm">
      {{ message }}
    </p>
    <ErrorAlert
      class="mt-3"
      :error="error"
    />
    <template #actions>
      <button
        type="button"
        class="btn"
        :disabled="busy"
        @click="open = false"
      >
        Cancel
      </button>
      <button
        type="button"
        class="btn"
        :class="danger ? 'btn-danger' : 'btn-primary'"
        :disabled="busy"
        @click="confirm"
      >
        {{ confirmLabel ?? label }}
      </button>
    </template>
  </ModalDialog>
</template>
