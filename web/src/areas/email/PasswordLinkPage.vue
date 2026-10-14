<script setup lang="ts">
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'
import { authn } from '@/api/authn'
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
const done = ref(false)
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

async function submit() {
  if (!token || busy.value) return
  error.value = passwordProblem(password.value, confirm.value)
  if (error.value) return
  busy.value = true
  try {
    await (props.mode === 'reset'
      ? authn.resetPassword(token, password.value)
      : authn.acceptInvite(token, password.value))
    done.value = true
  } catch (err) {
    error.value = linkError(err)
  } finally {
    busy.value = false
    password.value = ''
    confirm.value = ''
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
        {{ text.done }}
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
    </form>
  </AuthCard>
</template>
