<script setup lang="ts">
import { ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { me as meApi } from '@/api/me'
import type { TotpEnrollment } from '@/api/types'
import SecretOnceDialog from '@/components/SecretOnceDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import PasswordPrompt from './PasswordPrompt.vue'
import TotpEnrollDialog from './TotpEnrollDialog.vue'

type Prompt = 'enroll' | 'regenerate' | 'remove'

const auth = useAuthStore()
const { me } = storeToRefs(auth)
const prompt = ref<Prompt | null>(null)
const enrollment = ref<TotpEnrollment | null>(null)
const codes = ref<string[] | null>(null)

const refreshError = ref<string | null>(null)

/** Re-reads `me` after a change; a failure here must not look like the change failed. */
async function refresh() {
  refreshError.value = null
  try {
    auth.setMe(await meApi.get())
  } catch {
    refreshError.value =
      'Your change was saved, but this page could not be updated. Reload to see the current state.'
  }
}

const prompts: Record<
  Prompt,
  { title: string; message: string; confirm: string; danger?: boolean; run: (pw: string) => Promise<void> }
> = {
  enroll: {
    title: 'Set up an authenticator app',
    message: 'Confirm your password to add an authenticator app.',
    confirm: 'Continue',
    run: async (pw) => {
      enrollment.value = await meApi.beginTotp(pw)
      prompt.value = null
    },
  },
  regenerate: {
    title: 'New recovery codes',
    message: 'Your existing recovery codes stop working and 10 new ones are shown once.',
    confirm: 'Generate new codes',
    run: async (pw) => {
      codes.value = (await meApi.regenerateRecoveryCodes(pw)).recovery_codes
      prompt.value = null
      await refresh()
    },
  },
  remove: {
    title: 'Remove authenticator app?',
    message:
      'Sign-in will no longer ask for a second factor, and your recovery codes are deleted.',
    confirm: 'Remove',
    danger: true,
    run: async (pw) => {
      await meApi.removeTotp(pw)
      prompt.value = null
      await refresh()
    },
  },
}

async function confirmed(recovery: string[]) {
  enrollment.value = null
  codes.value = recovery
  await refresh()
}

async function runPrompt(pw: string) {
  if (prompt.value) await prompts[prompt.value].run(pw)
}
</script>

<template>
  <div
    v-if="me"
    class="space-y-6"
  >
    <ErrorAlert :error="refreshError" />
    <section class="card space-y-3">
      <h2 class="text-lg font-semibold">
        Two-step verification
      </h2>
      <template v-if="me.mfa.totp">
        <p class="text-sm">
          <span class="badge">On</span> Sign-in asks for a code from your authenticator app.
        </p>
        <p class="muted text-sm">
          Recovery codes left: <strong>{{ me.mfa.recovery_codes_remaining }}</strong>. Use one if
          you lose access to your app.
        </p>
        <div class="flex flex-wrap gap-2">
          <button
            type="button"
            class="btn"
            @click="prompt = 'regenerate'"
          >
            Get new recovery codes
          </button>
          <button
            type="button"
            class="btn text-red-700 dark:text-red-400"
            @click="prompt = 'remove'"
          >
            Remove authenticator app
          </button>
        </div>
      </template>
      <template v-else>
        <p class="text-sm">
          <span class="badge">Off</span> Protect your account with an authenticator app: sign-in
          will ask for a 6-digit code in addition to your password.
        </p>
        <button
          type="button"
          class="btn btn-primary"
          @click="prompt = 'enroll'"
        >
          Set up authenticator app
        </button>
      </template>
    </section>
    <PasswordPrompt
      :open="prompt !== null"
      :title="prompt ? prompts[prompt].title : ''"
      :message="prompt ? prompts[prompt].message : ''"
      :confirm-label="prompt ? prompts[prompt].confirm : ''"
      :danger="prompt ? prompts[prompt].danger : false"
      :action="runPrompt"
      @close="prompt = null"
    />
    <TotpEnrollDialog
      :enrollment="enrollment"
      @close="enrollment = null"
      @confirmed="confirmed"
    />
    <SecretOnceDialog
      title="Your recovery codes"
      description="Keep these somewhere safe (a password manager or printed). Each code signs you in once if you lose your authenticator app."
      :values="codes"
      filename="recovery-codes.txt"
      @close="codes = null"
    />
  </div>
</template>
