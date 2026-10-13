<script setup lang="ts">
import { ref, watch } from 'vue'
import { me as meApi } from '@/api/me'
import type { TotpEnrollment } from '@/api/types'
import { useAction } from '@/composables/useAction'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import QrCode from '@/components/QrCode.vue'
import CopyButton from '@/components/CopyButton.vue'

/** Second enrollment step: scan the pending secret, then confirm with a current code. */
const props = defineProps<{ enrollment: TotpEnrollment | null }>()
const emit = defineEmits<{ close: []; confirmed: [recoveryCodes: string[]] }>()

const code = ref('')
const { busy, error, run } = useAction()

watch(
  () => props.enrollment,
  () => {
    code.value = ''
    error.value = null
  },
)

async function confirm() {
  const res = await run(() => meApi.confirmTotp(code.value.replace(/\s/g, '')))
  if (res) emit('confirmed', res.recovery_codes)
}
</script>

<template>
  <ModalDialog
    :open="enrollment !== null"
    title="Set up your authenticator app"
    wide
    @close="emit('close')"
  >
    <div
      v-if="enrollment"
      class="space-y-4"
    >
      <ol class="list-decimal space-y-1 pl-5 text-sm">
        <li>Open an authenticator app (e.g. Microsoft Authenticator, Google Authenticator, 1Password).</li>
        <li>Scan the QR code, or enter the secret manually.</li>
        <li>Enter the 6-digit code the app shows.</li>
      </ol>
      <div class="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
        <QrCode
          :value="enrollment.otpauth_uri"
          label="QR code for your authenticator app"
        />
        <div class="min-w-0 flex-1 space-y-2 text-sm">
          <p class="muted">
            Secret ({{ enrollment.algorithm }}, {{ enrollment.digits }} digits,
            {{ enrollment.period }} s)
          </p>
          <p class="mono text-sm select-all">
            {{ enrollment.secret }}
          </p>
          <CopyButton
            :text="enrollment.secret"
            label="Copy secret"
          />
        </div>
      </div>
      <form
        id="totp-confirm"
        class="max-w-xs"
        @submit.prevent="confirm"
      >
        <label
          class="label"
          for="totp-code"
        >Code from the app</label>
        <input
          id="totp-code"
          v-model="code"
          class="input font-mono tracking-widest"
          inputmode="numeric"
          autocomplete="one-time-code"
          maxlength="7"
          required
        >
      </form>
      <ErrorAlert :error="error" />
    </div>
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
        form="totp-confirm"
        class="btn btn-primary"
        :disabled="busy"
      >
        Verify and turn on
      </button>
    </template>
  </ModalDialog>
</template>
