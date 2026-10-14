<script setup lang="ts">
import { onMounted, ref } from 'vue'

/** `passkey`: offer "Sign in with a passkey" (the step accepts one and the browser can). */
const props = defineProps<{
  locked: boolean
  canReset?: boolean
  initialEmail?: string
  passkey?: boolean
}>()
const emit = defineEmits<{
  submit: [email: string, password: string]
  forgot: [email: string]
  passkey: []
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
      >
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
    <template v-if="passkey">
      <p class="muted text-center text-xs">
        or
      </p>
      <button
        type="button"
        class="btn w-full"
        :disabled="locked"
        @click="emit('passkey')"
      >
        Sign in with a passkey
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
