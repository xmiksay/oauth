<script setup lang="ts">
import { nextTick, onMounted, ref, watch } from 'vue'

/** `sent`: a code went out in this step; until then only "Send code via Telegram" shows. */
const props = defineProps<{ locked: boolean; sent: boolean }>()
const emit = defineEmits<{ send: []; submit: [code: string] }>()

const code = ref('')
const input = ref<HTMLInputElement | null>(null)
const sendButton = ref<HTMLButtonElement | null>(null)

onMounted(() => (input.value ?? sendButton.value)?.focus())

// A new code replaces the previous one: drop what was typed and focus the input.
watch(
  () => props.sent,
  async (sent) => {
    if (!sent) return
    code.value = ''
    await nextTick()
    input.value?.focus()
  },
)

function resend() {
  code.value = ''
  emit('send')
}
</script>

<template>
  <div
    v-if="!sent"
    class="space-y-4"
  >
    <p class="muted text-sm">
      We'll send a 6-digit code to your linked Telegram account.
    </p>
    <button
      ref="sendButton"
      type="button"
      class="btn btn-primary w-full"
      :disabled="locked"
      @click="emit('send')"
    >
      Send code via Telegram
    </button>
  </div>
  <form
    v-else
    class="space-y-4"
    @submit.prevent="emit('submit', code)"
  >
    <p class="muted text-sm">
      Enter the 6-digit code we sent you on Telegram.
    </p>
    <div>
      <label
        class="label"
        for="telegram-code"
      >Telegram code</label>
      <input
        id="telegram-code"
        ref="input"
        v-model="code"
        class="input font-mono tracking-widest"
        inputmode="numeric"
        autocomplete="one-time-code"
        pattern="\s*\d{3}\s?\d{3}\s*"
        maxlength="7"
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
      :disabled="locked"
      @click="resend"
    >
      Send a new code
    </button>
  </form>
</template>
