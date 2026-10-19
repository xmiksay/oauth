<script setup lang="ts">
import { onMounted, ref } from 'vue'
import type { IdpRef } from '@/api/types'

/**
 * `passkey`: offer "Sign in with a passkey" (the step accepts one and the browser can);
 * `idps`: "Sign in with …" buttons; `suggestion`: the provider the email's domain belongs to.
 */
const props = defineProps<{
  locked: boolean
  canReset?: boolean
  initialEmail?: string
  passkey?: boolean
  idps?: IdpRef[]
  suggestion?: IdpRef | null
}>()
const emit = defineEmits<{
  submit: [email: string, password: string]
  forgot: [email: string]
  passkey: []
  federate: [idp: IdpRef]
  discover: [email: string]
}>()

const email = ref(props.initialEmail ?? '')
const password = ref('')
const first = ref<HTMLInputElement | null>(null)
// Steps swap in place; move focus so keyboard and screen-reader users land on the new step.
onMounted(() => first.value?.focus())
</script>

<template>
  <form
    class="space-y-4"
    @submit.prevent="emit('submit', email.trim(), password)"
  >
    <div>
      <label
        class="label"
        for="login-email"
      >Email</label>
      <!-- `webauthn` lets the browser offer passkeys in this field's autofill. -->
      <input
        id="login-email"
        ref="first"
        v-model="email"
        class="input"
        type="email"
        :autocomplete="passkey ? 'username webauthn' : 'username'"
        required
        @blur="emit('discover', email.trim())"
      >
    </div>
    <div
      v-if="suggestion"
      class="space-y-2 rounded-md border border-sky-300 bg-sky-50 px-3 py-2 text-sm text-sky-900 dark:border-sky-700 dark:bg-sky-950 dark:text-sky-100"
      data-testid="idp-suggestion"
    >
      <p role="status">
        Your organization signs in with {{ suggestion.name }}.
      </p>
      <button
        type="button"
        class="btn w-full"
        :disabled="locked"
        @click="emit('federate', suggestion)"
      >
        Continue with {{ suggestion.name }}
      </button>
    </div>
    <div>
      <label
        class="label"
        for="login-password"
      >Password</label>
      <input
        id="login-password"
        v-model="password"
        class="input"
        type="password"
        autocomplete="current-password"
        required
      >
    </div>
    <button
      type="submit"
      class="btn btn-primary w-full"
      :disabled="locked"
    >
      Sign in
    </button>
    <template v-if="passkey || idps?.length">
      <p class="muted text-center text-xs">
        or
      </p>
      <button
        v-if="passkey"
        type="button"
        class="btn w-full"
        :disabled="locked"
        @click="emit('passkey')"
      >
        Sign in with a passkey
      </button>
      <button
        v-for="idp in idps"
        :key="idp.id"
        type="button"
        class="btn w-full"
        :disabled="locked"
        @click="emit('federate', idp)"
      >
        Sign in with {{ idp.name }}
      </button>
    </template>
    <button
      v-if="canReset"
      type="button"
      class="btn-link"
      @click="emit('forgot', email.trim())"
    >
      Forgot password?
    </button>
  </form>
</template>
