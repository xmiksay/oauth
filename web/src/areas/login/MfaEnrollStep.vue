<script setup lang="ts">
import { onMounted, ref } from 'vue'
import type { TotpEnrollment } from '@/api/types'
import QrCode from '@/components/QrCode.vue'
import CopyButton from '@/components/CopyButton.vue'
import SecretOnceDialog from '@/components/SecretOnceDialog.vue'

/**
 * `mfa_enroll`: MFA is required and the user has no second factor. They set up an
 * authenticator app (TOTP) or a passkey; either completes this sign-in's MFA.
 */
const props = defineProps<{
  locked: boolean
  /** A factor was set up already (e.g. before a reload): only continuing is left. */
  enrolled: boolean
  /** The browser can create passkeys. */
  passkeys: boolean
  begin: () => Promise<TotpEnrollment | null>
  confirm: (code: string) => Promise<string[] | null>
}>()
const emit = defineEmits<{ passkey: []; done: [] }>()

// Secret-once: the pending secret and the recovery codes live only in this component.
const enrollment = ref<TotpEnrollment | null>(null)
const codes = ref<string[] | null>(null)
const code = ref('')

async function startTotp() {
  enrollment.value = await props.begin()
}

async function submit() {
  const result = await props.confirm(code.value)
  if (!result) return
  enrollment.value = null
  code.value = ''
  codes.value = result
}

function closeCodes() {
  codes.value = null
  emit('done')
}

const first = ref<HTMLButtonElement | null>(null)
// Steps swap in place; move focus so keyboard and screen-reader users land on the new step.
onMounted(() => first.value?.focus())
</script>

<template>
  <div class="space-y-4">
    <template v-if="enrolled && !codes">
      <p class="muted text-sm">
        Your second way to verify it's you is set up.
      </p>
      <button
        ref="first"
        type="button"
        class="btn btn-primary w-full"
        :disabled="locked"
        @click="emit('done')"
      >
        Continue
      </button>
    </template>
    <template v-else-if="!enrollment">
      <p class="muted text-sm">
        Your organization requires a second way to verify it's you. Set one up to continue.
      </p>
      <button
        ref="first"
        type="button"
        class="btn btn-primary w-full"
        :disabled="locked"
        @click="startTotp"
      >
        Use an authenticator app
      </button>
      <button
        v-if="passkeys"
        type="button"
        class="btn w-full"
        :disabled="locked"
        @click="emit('passkey')"
      >
        Create a passkey
      </button>
    </template>
    <form
      v-else
      class="space-y-4"
      @submit.prevent="submit"
    >
      <p class="muted text-sm">
        Scan the QR code with your authenticator app (or enter the secret), then enter the
        6-digit code it shows.
      </p>
      <div class="flex flex-col items-center gap-3">
        <QrCode
          :value="enrollment.otpauth_uri"
          label="QR code for your authenticator app"
        />
        <p class="mono text-sm select-all break-all">
          {{ enrollment.secret }}
        </p>
        <CopyButton
          :text="enrollment.secret"
          label="Copy secret"
        />
      </div>
      <div>
        <label
          class="label"
          for="enroll-code"
        >Code from the app</label>
        <input
          id="enroll-code"
          v-model="code"
          class="input font-mono tracking-widest"
          inputmode="numeric"
          autocomplete="one-time-code"
          maxlength="7"
          required
        >
      </div>
      <button
        type="submit"
        class="btn btn-primary w-full"
        :disabled="locked"
      >
        Verify and continue
      </button>
    </form>
    <SecretOnceDialog
      title="Save your recovery codes"
      :values="codes"
      description="Each code signs you in once if you lose your authenticator. They won't be shown again."
      filename="recovery-codes.txt"
      @close="closeCodes"
    />
  </div>
</template>
