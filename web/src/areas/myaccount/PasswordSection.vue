<script setup lang="ts">
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { me as meApi } from '@/api/me'
import { passkeysSupported } from '@/webauthn'
import { useAction } from '@/composables/useAction'
import { PASSWORD_MIN, passwordProblem } from '@/lib/format'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'
import { passkeyReauth, reauthError } from './reauth'

/** Change the password, or — for a passkey-only user — set a first one, confirmed with a passkey. */
const auth = useAuthStore()
const { me } = storeToRefs(auth)
const hasPassword = computed(() => me.value?.has_password ?? true)
// Setting a first password is confirmed with a passkey, which needs WebAuthn.
const blocked = computed(() => !hasPassword.value && !passkeysSupported())

const current = ref('')
const next = ref('')
const confirm = ref('')
const pw = useAction()
const done = ref<string | null>(null)

async function submit() {
  done.value = null
  const problem = passwordProblem(next.value, confirm.value)
  if (problem) {
    pw.error.value = problem
    return
  }
  const setting = !hasPassword.value
  const ok = await pw.run(async () => {
    try {
      const reauth = setting ? await passkeyReauth() : { password: current.value }
      await meApi.changePassword(next.value, reauth)
    } catch (err) {
      throw reauthError(err, setting ? 'passkey' : 'password')
    }
    return true
  })
  current.value = ''
  next.value = ''
  confirm.value = ''
  if (!ok) return
  done.value = setting
    ? 'Password set. You can now sign in with it or with a passkey.'
    : 'Password changed. Your other sessions have been signed out.'
  if (setting) {
    // `has_password` flips; a failed refresh only leaves this form in its old mode.
    await meApi.get().then(auth.setMe, () => undefined)
  }
}
</script>

<template>
  <form
    v-if="me"
    class="card space-y-4"
    novalidate
    @submit.prevent="submit"
    @input="done = null"
  >
    <h2 class="text-lg font-semibold">
      {{ hasPassword ? 'Password' : 'Set a password' }}
    </h2>
    <p
      v-if="hasPassword"
      class="muted text-sm"
    >
      Changing your password signs you out on every other device and app. This browser stays
      signed in.
    </p>
    <p
      v-else
      class="muted text-sm"
    >
      You sign in with a passkey. Add a password as another way to sign in; you'll confirm
      with one of your passkeys.
    </p>
    <p
      v-if="blocked"
      role="alert"
      class="text-sm"
    >
      This browser can't use passkeys. Set a password from a browser or device that supports
      them.
    </p>
    <div class="grid max-w-md gap-4">
      <div v-if="hasPassword">
        <label
          class="label"
          for="pw-current"
        >Current password</label>
        <input
          id="pw-current"
          v-model="current"
          class="input"
          type="password"
          autocomplete="current-password"
          required
        >
      </div>
      <div>
        <label
          class="label"
          for="pw-new"
        >New password</label>
        <input
          id="pw-new"
          v-model="next"
          class="input"
          type="password"
          autocomplete="new-password"
          required
        >
        <p class="hint">
          At least {{ PASSWORD_MIN }} characters.
        </p>
      </div>
      <div>
        <label
          class="label"
          for="pw-confirm"
        >Confirm new password</label>
        <input
          id="pw-confirm"
          v-model="confirm"
          class="input"
          type="password"
          autocomplete="new-password"
          required
        >
      </div>
    </div>
    <ErrorAlert :error="pw.error.value" />
    <StatusNote :message="done" />
    <button
      type="submit"
      class="btn btn-primary"
      :disabled="pw.busy.value || blocked || (hasPassword && !current)"
    >
      {{ hasPassword ? 'Change password' : 'Set password' }}
    </button>
  </form>
</template>
