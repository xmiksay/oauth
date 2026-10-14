<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ApiError, errorMessage } from '@/api/client'
import { authn } from '@/api/authn'
import ErrorAlert from '@/components/ErrorAlert.vue'

/** Requests a password-reset link; the sign-in transaction stays where it was. */
const props = defineProps<{ initialEmail: string }>()
const emit = defineEmits<{ back: [email: string] }>()

const email = ref(props.initialEmail)
const busy = ref(false)
const sent = ref(false)
const error = ref<string | null>(null)
const first = ref<HTMLInputElement | null>(null)
onMounted(() => first.value?.focus())

function messageFor(err: unknown): string {
  if (err instanceof ApiError && err.status === 404) {
    return "Password reset isn't available here. Contact your administrator."
  }
  if (err instanceof ApiError && err.status === 400) return 'Enter a valid email address.'
  return errorMessage(err)
}

async function submit() {
  if (busy.value) return
  busy.value = true
  error.value = null
  try {
    await authn.requestPasswordReset(email.value.trim())
    sent.value = true
  } catch (err) {
    error.value = messageFor(err)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="space-y-4">
    <!-- Worded the same whether or not the account exists: the server never tells either. -->
    <p
      v-if="sent"
      class="text-sm"
      aria-live="polite"
    >
      If an account exists for that address, we sent a link to reset the password. It expires
      in 30 minutes.
    </p>
    <form
      v-else
      class="space-y-4"
      @submit.prevent="submit"
    >
      <p class="muted text-sm">
        Enter your email and we'll send you a link to choose a new password.
      </p>
      <div>
        <label
          class="label"
          for="forgot-email"
        >Email</label>
        <input
          id="forgot-email"
          ref="first"
          v-model="email"
          class="input"
          type="email"
          autocomplete="username"
          required
        >
      </div>
      <ErrorAlert :error="error" />
      <button
        type="submit"
        class="btn btn-primary w-full"
        :disabled="busy"
      >
        Send reset link
      </button>
    </form>
    <button
      type="button"
      class="btn-link"
      @click="emit('back', email.trim())"
    >
      Back to sign in
    </button>
  </div>
</template>
