<script setup lang="ts">
import { ref, watch } from 'vue'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import { passwordError } from './passwordError'

/**
 * Re-asks for the current password before a security-info change, then runs `action`.
 * The default slot adds fields above the password (their state stays with the caller).
 */
const props = defineProps<{
  open: boolean
  title: string
  message: string
  confirmLabel: string
  danger?: boolean
  action: (password: string) => Promise<unknown>
}>()
const emit = defineEmits<{ close: [] }>()

const password = ref('')
const busy = ref(false)
const error = ref<unknown>(null)

watch(
  () => props.open,
  () => {
    password.value = ''
    error.value = null
  },
)

async function submit() {
  busy.value = true
  error.value = null
  try {
    await props.action(password.value)
  } catch (err) {
    error.value = passwordError(err)
  } finally {
    busy.value = false
    password.value = ''
  }
}
</script>

<template>
  <ModalDialog
    :open="open"
    :title="title"
    @close="emit('close')"
  >
    <form
      id="password-prompt"
      class="space-y-4"
      @submit.prevent="submit"
    >
      <p class="text-sm">
        {{ message }}
      </p>
      <slot />
      <div>
        <label
          class="label"
          for="pp-password"
        >Current password</label>
        <input
          id="pp-password"
          v-model="password"
          class="input"
          type="password"
          autocomplete="current-password"
          required
          autofocus
        >
      </div>
      <ErrorAlert :error="error" />
    </form>
    <template #actions>
      <button
        type="button"
        class="btn"
        @click="emit('close')"
      >
        Cancel
      </button>
      <button
        type="submit"
        form="password-prompt"
        class="btn"
        :class="danger ? 'btn-danger' : 'btn-primary'"
        :disabled="busy || !password"
      >
        {{ confirmLabel }}
      </button>
    </template>
  </ModalDialog>
</template>
