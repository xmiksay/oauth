<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from 'vue'
import type { LoginFactor } from '@/api/authn'
import TelegramFactor from './TelegramFactor.vue'

/**
 * `factors`: what this user has; `passkeys`: whether this browser can use one;
 * `telegramSent`: a Telegram code went out in this step.
 */
const props = defineProps<{
  locked: boolean
  factors: LoginFactor[]
  passkeys: boolean
  telegramSent?: boolean
}>()
const emit = defineEmits<{
  totp: [code: string]
  recovery: [code: string]
  passkey: []
  telegramSend: []
  telegram: [code: string]
}>()

type CodeMode = 'totp' | 'telegram' | 'recovery'

// Order = preference for the initial mode; recovery codes are the fallback.
const codeModes = computed(() =>
  (['totp', 'telegram', 'recovery'] as const).filter((f) => props.factors.includes(f)),
)
const SWITCH_LABELS: Record<CodeMode, string> = {
  totp: 'Use my authenticator app instead',
  telegram: 'Get a code via Telegram instead',
  recovery: 'Use a recovery code instead',
}
const offersPasskey = computed(() => props.factors.includes('passkey'))
const mode = ref<CodeMode | null>(codeModes.value[0] ?? null)
const others = computed(() => codeModes.value.filter((m) => m !== mode.value))
const code = ref('')
const input = ref<HTMLInputElement | null>(null)
const focusTarget = ref<HTMLButtonElement | null>(null)

async function switchTo(next: CodeMode) {
  mode.value = next
  code.value = ''
  await nextTick()
  input.value?.focus()
}

// TelegramFactor focuses its own control.
onMounted(() => {
  if (mode.value !== 'telegram') (input.value ?? focusTarget.value)?.focus()
})

function submit() {
  if (mode.value === 'recovery') emit('recovery', code.value.trim())
  else emit('totp', code.value)
}
</script>

<template>
  <div class="space-y-4">
    <TelegramFactor
      v-if="mode === 'telegram'"
      :locked="locked"
      :sent="telegramSent ?? false"
      @send="emit('telegramSend')"
      @submit="(c) => emit('telegram', c)"
    />
    <form
      v-else-if="mode"
      class="space-y-4"
      @submit.prevent="submit"
    >
      <p class="muted text-sm">
        {{
          mode === 'recovery'
            ? 'Enter one of the recovery codes you saved when you set up your authenticator app. Each code works once.'
            : 'Enter the 6-digit code from your authenticator app.'
        }}
      </p>
      <div>
        <label
          class="label"
          for="mfa-code"
        >{{ mode === 'recovery' ? 'Recovery code' : 'Verification code' }}</label>
        <input
          v-if="mode === 'totp'"
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
    </form>
    <div
      v-if="others.length"
      class="flex flex-col items-start gap-1"
    >
      <button
        v-for="m in others"
        :key="m"
        type="button"
        class="btn-link"
        @click="switchTo(m)"
      >
        {{ SWITCH_LABELS[m] }}
      </button>
    </div>
    <template v-if="offersPasskey">
      <p
        v-if="!mode"
        class="muted text-sm"
      >
        Confirm it's you with your passkey.
      </p>
      <button
        v-if="passkeys"
        ref="focusTarget"
        type="button"
        class="btn w-full"
        :class="{ 'btn-primary': !mode }"
        :disabled="locked"
        @click="emit('passkey')"
      >
        Use a passkey
      </button>
      <p
        v-else-if="!mode"
        role="alert"
        class="text-sm"
      >
        This browser can't use passkeys. Sign in from a browser or device that supports them.
      </p>
    </template>
  </div>
</template>
