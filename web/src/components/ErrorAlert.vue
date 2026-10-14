<script setup lang="ts">
import { computed } from 'vue'
import { ApiError, errorMessage } from '@/api/client'
import { SignInRequired } from '@/stores/auth'
import { PasskeyCancelled } from '@/webauthn'

/**
 * Renders an error from any request (nothing for `null` or a pending re-auth). A dismissed
 * passkey dialog is the user's choice, so it gets a plain note instead of an alert.
 */
const props = defineProps<{ error: unknown }>()

const cancelled = computed(() => props.error instanceof PasskeyCancelled)

const message = computed(() => {
  const e = props.error
  // A 401 already started the re-auth redirect (or set the area's fatal message).
  if (e === null || e === undefined || e instanceof SignInRequired) return null
  if (e instanceof PasskeyCancelled) return e.message
  if (e instanceof ApiError && e.status === 401) return null
  if (e instanceof ApiError && e.status === 403) {
    return `You don't have permission to do this. ${e.description ?? ''}`.trim()
  }
  return typeof e === 'string' ? e : errorMessage(e)
})
</script>

<template>
  <p
    v-if="cancelled"
    role="status"
    class="muted text-sm"
  >
    {{ message }}
  </p>
  <div
    v-else-if="message"
    role="alert"
    class="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200"
  >
    {{ message }}
  </div>
</template>
