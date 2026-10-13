<script setup lang="ts">
import { nextTick, onMounted, ref } from 'vue'

defineProps<{ locked: boolean }>()
const emit = defineEmits<{ totp: [code: string]; recovery: [code: string] }>()

const useRecovery = ref(false)
const code = ref('')
const input = ref<HTMLInputElement | null>(null)

async function toggle() {
  useRecovery.value = !useRecovery.value
  code.value = ''
  await nextTick()
  input.value?.focus()
}

onMounted(() => input.value?.focus())

function submit() {
  if (useRecovery.value) emit('recovery', code.value.trim())
  else emit('totp', code.value)
}
</script>

<template>
  <form
    class="space-y-4"
    @submit.prevent="submit"
  >
    <p class="muted text-sm">
      {{
        useRecovery
          ? 'Enter one of the recovery codes you saved when you set up your authenticator app. Each code works once.'
          : 'Enter the 6-digit code from your authenticator app.'
      }}
    </p>
    <div>
      <label
        class="label"
        for="mfa-code"
      >{{ useRecovery ? 'Recovery code' : 'Verification code' }}</label>
      <input
        v-if="!useRecovery"
        id="mfa-code"
        ref="input"
        v-model="code"
        class="input font-mono tracking-widest"
        inputmode="numeric"
        autocomplete="one-time-code"
        pattern="\s*\d{3}\s?\d{3}\s*"
        maxlength="7"
        required
      >
      <input
        v-else
        id="mfa-code"
        ref="input"
        v-model="code"
        class="input font-mono"
        autocomplete="off"
        spellcheck="false"
        placeholder="xxxx-xxxx-xxxx"
        required
      >
    </div>
    <button
      type="submit"
      class="btn btn-primary w-full"
      :disabled="locked"
    >
      Verify
    </button>
    <button
      type="button"
      class="btn-link"
      @click="toggle"
    >
      {{ useRecovery ? 'Use my authenticator app instead' : 'Use a recovery code instead' }}
    </button>
  </form>
</template>
