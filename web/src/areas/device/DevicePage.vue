<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'
import { ApiError, errorMessage } from '@/api/client'
import { authn } from '@/api/authn'
import { isWebUrl, navigateTo } from '@/lib/navigate'
import AuthCard from '@/components/AuthCard.vue'

/**
 * `/device` — the device code grant's verification page (RFC 8628). The user types the code
 * their device shows (or arrives with `?user_code=` from `verification_uri_complete`, still
 * confirmed by a click); the server starts a sign-in for it on `/login`, which ends back here
 * with `?result=approved` or `?error=…`.
 */
const route = useRoute()
const router = useRouter()
const { slug } = storeToRefs(useTenantStore())

const param = (key: string) => {
  const v = route.query[key]
  return typeof v === 'string' && v ? v : null
}
const code = ref(param('user_code') ?? '')
const approved = param('result') === 'approved'
const outcome = param('error')
// The code stays in the form only, not in the address bar or history.
if (param('user_code') !== null) void router.replace({ query: {} })

const OUTCOMES: Record<string, string> = {
  access_denied: 'You denied the sign-in. The device was not signed in.',
  consent_required:
    "An administrator must approve this app's permissions before you can sign in with it.",
  expired_token: 'The code expired before you finished. Start again on your device.',
  login_required: 'Your session ended before you finished. Enter the code again.',
}
const outcomeText = outcome
  ? (OUTCOMES[outcome] ?? "The device sign-in didn't complete. Start again on your device.")
  : null

const busy = ref(false)
const error = ref<string | null>(null)
const title = computed(() => (approved ? 'Device signed in' : 'Sign in on a device'))

function messageFor(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.code === 'invalid_code') {
      return 'That code is invalid or has expired. Check the code on your device and try again.'
    }
    if (err.status === 429) return 'Too many attempts. Wait a few minutes and try again.'
  }
  return errorMessage(err)
}

async function submit() {
  if (busy.value || !code.value.trim()) return
  busy.value = true
  error.value = null
  try {
    const { redirect } = await authn.deviceCode(code.value.trim())
    if (!isWebUrl(redirect)) throw new Error('unexpected redirect')
    navigateTo(redirect)
  } catch (err) {
    error.value = messageFor(err)
    busy.value = false
  }
}
</script>

<template>
  <AuthCard
    :title="title"
    :tenant="slug"
  >
    <div
      v-if="approved"
      class="space-y-2"
      aria-live="polite"
    >
      <p class="text-sm">
        Your device is now signed in. You can close this window and continue on the device.
      </p>
    </div>
    <form
      v-else
      class="space-y-4"
      @submit.prevent="submit"
    >
      <p
        v-if="outcomeText"
        role="alert"
        class="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
      >
        {{ outcomeText }}
      </p>
      <div>
        <label
          class="label"
          for="device-code"
        >Code</label>
        <input
          id="device-code"
          v-model="code"
          class="input font-mono uppercase tracking-widest"
          autocomplete="off"
          autocapitalize="characters"
          spellcheck="false"
          maxlength="16"
          required
          aria-describedby="device-code-hint"
        >
        <p
          id="device-code-hint"
          class="hint"
        >
          Enter the code your device shows, for example BDFG-KLMN. Only enter a code from a device
          you are using yourself.
        </p>
      </div>
      <p
        v-if="error"
        role="alert"
        class="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200"
      >
        {{ error }}
      </p>
      <button
        type="submit"
        class="btn btn-primary w-full"
        :disabled="busy"
      >
        Continue
      </button>
    </form>
  </AuthCard>
</template>
