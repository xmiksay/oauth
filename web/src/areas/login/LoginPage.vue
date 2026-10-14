<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'
import AuthCard from '@/components/AuthCard.vue'
import PasswordStep from './PasswordStep.vue'
import MfaStep from './MfaStep.vue'
import ChangePasswordStep from './ChangePasswordStep.vue'
import ConsentStep from './ConsentStep.vue'
import ForgotPasswordForm from './ForgotPasswordForm.vue'
import { passkeysSupported } from '@/webauthn'
import { useLoginFlow } from './useLoginFlow'

const route = useRoute()
const { slug } = storeToRefs(useTenantStore())
const tx = typeof route.query.tx === 'string' && route.query.tx ? route.query.tx : null

const flow = useLoginFlow(tx)
const { phase, view, error, notice, locked, rateLimited, retryIn } = flow

onMounted(flow.load)
onUnmounted(flow.dispose)

// The reset request is a detour within the password step; the tx stays untouched.
const forgot = ref(false)
const email = ref('')
function toggleForgot(show: boolean, typed: string) {
  email.value = typed
  forgot.value = show
}

const canUsePasskeys = passkeysSupported()
const factors = computed(() => view.value?.factors ?? [])
const offerPasskey = computed(() => canUsePasskeys && factors.value.includes('passkey'))

// Autofill passkeys only while the email field is on screen and nothing else is in flight;
// any other request (password, modal passkey) cancels it and it restarts with fresh options.
watch(
  () =>
    offerPasskey.value &&
    phase.value === 'step' &&
    view.value?.step === 'password' &&
    !forgot.value &&
    !locked.value,
  (on) => (on ? void flow.startConditional() : flow.stopConditional()),
  { flush: 'post' },
)

const title = computed(() => {
  if (forgot.value && view.value?.step === 'password') return 'Reset your password'
  switch (view.value?.step) {
    case 'mfa':
      return 'Verify your identity'
    case 'change_password':
      return 'Update your password'
    case 'consent':
      return 'Permissions requested'
    default:
      return 'Sign in'
  }
})

const subtitle = computed(() => {
  const v = view.value
  if (!v) return null
  if (v.step === 'password') return forgot.value ? null : `to continue to ${v.client.display_name}`
  return v.user ? v.user.email : null
})
</script>

<template>
  <AuthCard
    :title="phase === 'step' ? title : 'Sign in'"
    :tenant="view?.tenant.display_name ?? slug"
    :subtitle="phase === 'step' ? subtitle : null"
  >
    <p
      v-if="phase === 'loading'"
      class="muted"
      aria-live="polite"
    >
      Loading…
    </p>
    <p
      v-else-if="phase === 'redirecting'"
      class="muted"
      aria-live="polite"
    >
      Signing you in…
    </p>
    <div
      v-else-if="phase === 'expired'"
      role="alert"
      class="space-y-2"
    >
      <p class="font-medium">
        This sign-in has expired.
      </p>
      <p class="muted text-sm">
        Sign-in requests are valid for 15 minutes and work only in the browser that started
        them. Go back to the application you were signing in to and start again.
      </p>
    </div>
    <p
      v-else-if="phase === 'missing'"
      class="muted"
    >
      To sign in, open the application you want to use — it will bring you here.
    </p>
    <div
      v-else-if="phase === 'error'"
      class="space-y-4"
    >
      <p
        role="alert"
        class="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200"
      >
        {{ error }}
      </p>
      <button
        type="button"
        class="btn btn-primary w-full"
        @click="flow.load"
      >
        Try again
      </button>
    </div>
    <ForgotPasswordForm
      v-else-if="view?.step === 'password' && forgot"
      :initial-email="email"
      @back="(typed) => toggleForgot(false, typed)"
    />
    <template v-else-if="view">
      <div
        v-if="rateLimited"
        class="mb-4 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
      >
        <!-- Announced once; the ticking seconds stay outside the live region. -->
        <p role="alert">
          Too many attempts. Please wait before trying again.
        </p>
        <p
          aria-live="off"
          data-testid="retry-countdown"
        >
          Try again in {{ retryIn }} s.
        </p>
      </div>
      <p
        v-else-if="error"
        role="alert"
        class="mb-4 rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200"
      >
        {{ error }}
      </p>
      <p
        v-else-if="notice"
        role="status"
        class="muted mb-4 text-sm"
      >
        {{ notice }}
      </p>
      <PasswordStep
        v-if="view.step === 'password'"
        :locked="locked"
        :can-reset="view.features.password_reset"
        :initial-email="email"
        :passkey="offerPasskey"
        @submit="flow.password"
        @passkey="flow.passkey"
        @forgot="(typed) => toggleForgot(true, typed)"
      />
      <MfaStep
        v-else-if="view.step === 'mfa'"
        :locked="locked"
        :factors="factors"
        :passkeys="canUsePasskeys"
        @totp="flow.totp"
        @recovery="flow.recovery"
        @passkey="flow.passkey"
      />
      <ChangePasswordStep
        v-else-if="view.step === 'change_password'"
        :locked="locked"
        @submit="flow.changePassword"
      />
      <ConsentStep
        v-else-if="view.step === 'consent'"
        :view="view"
        :locked="locked"
        @decide="flow.consent"
      />
    </template>
  </AuthCard>
</template>
