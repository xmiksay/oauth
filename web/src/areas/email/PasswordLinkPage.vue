<script setup lang="ts">
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'
import { authn } from '@/api/authn'
import { ApiError } from '@/api/client'
import { PasskeyCancelled, createPasskey, passkeysSupported } from '@/webauthn'
import { PASSWORD_MIN, passwordProblem } from '@/lib/format'
import AuthCard from '@/components/AuthCard.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import { INVALID_LINK, linkError, useLinkToken } from './useLinkToken'

/** `/login/reset` and `/login/invite`: choose a password from an emailed link. */
const props = defineProps<{ mode: 'reset' | 'invite' }>()

const { slug } = storeToRefs(useTenantStore())
const token = useLinkToken()

const password = ref('')
const confirm = ref('')
const busy = ref(false)
const error = ref<string | null>(token ? null : INVALID_LINK)
const done = ref<'password' | 'passkey' | null>(null)
const cancelled = ref(false)
const offerPasskey = props.mode === 'invite' && passkeysSupported()
// A dead link can't be retried, so the form goes away with it.
const dead = computed(() => error.value === INVALID_LINK)

const text = computed(() =>
  props.mode === 'reset'
    ? {
        title: 'Reset your password',
        intro: 'Choose a new password for your account.',
        submit: 'Change password',
        doneTitle: 'Password changed',
        done: 'Your password was changed and you were signed out everywhere. Return to the application and sign in again.',
      }
    : {
        title: 'Set your password',
        intro: 'Choose a password to finish setting up your account.',
        submit: 'Set password',
        doneTitle: 'Your account is ready',
        done: 'Your password is set and your email address is verified. Return to the application and sign in with your new password.',
      },
)

const doneText = computed(() =>
  done.value === 'passkey'
    ? 'Your passkey is created and your email address is verified. Return to the application and sign in with your passkey.'
    : text.value.done,
)

async function submit() {
  if (!token || busy.value) return
  error.value = passwordProblem(password.value, confirm.value)
  if (error.value) return
  busy.value = true
  try {
    await (props.mode === 'reset'
      ? authn.resetPassword(token, password.value)
      : authn.acceptInvite(token, password.value))
    done.value = 'password'
  } catch (err) {
    error.value = linkError(err)
  } finally {
    busy.value = false
    password.value = ''
    confirm.value = ''
  }
}

async function createInstead() {
  if (!token || busy.value) return
  busy.value = true
  error.value = null
  cancelled.value = false
  try {
    const credential = await createPasskey(await authn.invitePasskeyOptions(token))
    await authn.acceptInviteWithPasskey(token, credential)
    done.value = 'passkey'
  } catch (err) {
    if (err instanceof PasskeyCancelled) cancelled.value = true
    else if (err instanceof ApiError && err.code === 'invalid_request')
      error.value = "That passkey couldn't be registered."
    else error.value = typeof err === 'string' ? err : linkError(err)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <AuthCard
    :title="done ? text.doneTitle : text.title"
    :tenant="slug"
  >
    <div
      v-if="done"
      class="space-y-4"
      aria-live="polite"
    >
      <p class="text-sm">
        {{ doneText }}
      </p>
      <RouterLink
        :to="{ name: 'myaccount' }"
        class="btn-link"
      >
        Go to My Account
      </RouterLink>
    </div>
    <ErrorAlert
      v-else-if="dead"
      :error="error"
    />
    <form
      v-else
      class="space-y-4"
      novalidate
      @submit.prevent="submit"
    >
      <p class="muted text-sm">
        {{ text.intro }}
      </p>
      <div>
        <label
          class="label"
          for="link-password"
        >New password</label>
        <input
          id="link-password"
          v-model="password"
          class="input"
          type="password"
          autocomplete="new-password"
          aria-describedby="link-password-hint"
          required
          autofocus
        >
        <p
          id="link-password-hint"
          class="hint"
        >
          At least {{ PASSWORD_MIN }} characters.
        </p>
      </div>
      <div>
        <label
          class="label"
          for="link-confirm"
        >Confirm new password</label>
        <input
          id="link-confirm"
          v-model="confirm"
          class="input"
          type="password"
          autocomplete="new-password"
          required
        >
      </div>
      <ErrorAlert :error="error" />
      <button
        type="submit"
        class="btn btn-primary w-full"
        :disabled="busy"
      >
        {{ text.submit }}
      </button>
      <template v-if="offerPasskey">
        <p class="muted text-center text-xs">
          or
        </p>
        <button
          type="button"
          class="btn w-full"
          :disabled="busy"
          @click="createInstead"
        >
          Create a passkey instead
        </button>
        <p
          role="status"
          class="muted text-sm"
        >
          {{ cancelled ? 'Passkey creation was cancelled.' : '' }}
        </p>
      </template>
    </form>
  </AuthCard>
</template>
