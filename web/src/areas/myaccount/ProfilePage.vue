<script setup lang="ts">
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { me as meApi } from '@/api/me'
import { ROLE_LABELS } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { PASSWORD_MIN, passwordProblem } from '@/lib/format'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'
import { passwordError } from './passwordError'
import EmailSection from './EmailSection.vue'

const auth = useAuthStore()
const { me, isAdmin } = storeToRefs(auth)
const roleNames = computed(() =>
  (me.value?.directory_roles ?? []).map((r) => ROLE_LABELS[r]).join(', '),
)

const name = ref(me.value?.display_name ?? '')
const profile = useAction()
const profileSaved = ref(false)

async function saveProfile() {
  profileSaved.value = false
  const updated = await profile.run(() => meApi.update({ display_name: name.value.trim() }))
  if (updated) {
    auth.setMe(updated)
    profileSaved.value = true
  }
}

const current = ref('')
const next = ref('')
const confirm = ref('')
const pw = useAction()
const pwChanged = ref(false)

async function changePassword() {
  pwChanged.value = false
  const problem = passwordProblem(next.value, confirm.value)
  if (problem) {
    pw.error.value = problem
    return
  }
  const ok = await pw.run(() =>
    meApi.changePassword(current.value, next.value).then(
      () => true,
      (err: unknown) => Promise.reject(passwordError(err)),
    ),
  )
  current.value = ''
  next.value = ''
  confirm.value = ''
  pwChanged.value = !!ok
}
</script>

<template>
  <div
    v-if="me"
    class="space-y-6"
  >
    <form
      class="card space-y-4"
      @submit.prevent="saveProfile"
      @input="profileSaved = false"
    >
      <h2 class="text-lg font-semibold">
        Profile
      </h2>
      <dl
        v-if="me.directory_roles.length"
        class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm"
      >
        <dt class="muted">
          Directory roles
        </dt>
        <dd>{{ roleNames }}</dd>
      </dl>
      <div class="max-w-md">
        <label
          class="label"
          for="pf-name"
        >Display name</label>
        <input
          id="pf-name"
          v-model="name"
          class="input"
          required
        >
      </div>
      <ErrorAlert :error="profile.error.value" />
      <StatusNote :message="profileSaved ? 'Saved.' : null" />
      <div class="flex flex-wrap items-center gap-3">
        <button
          type="submit"
          class="btn btn-primary"
          :disabled="profile.busy.value"
        >
          Save
        </button>
        <RouterLink
          v-if="isAdmin"
          :to="{ name: 'admin' }"
          class="btn-link"
        >
          Open the admin center
        </RouterLink>
      </div>
    </form>

    <EmailSection />

    <form
      class="card space-y-4"
      novalidate
      @submit.prevent="changePassword"
      @input="pwChanged = false"
    >
      <h2 class="text-lg font-semibold">
        Password
      </h2>
      <p class="muted text-sm">
        Changing your password signs you out on every other device and app. This browser stays
        signed in.
      </p>
      <div class="grid max-w-md gap-4">
        <div>
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
      <StatusNote :message="pwChanged ? 'Password changed. Your other sessions have been signed out.' : null" />
      <button
        type="submit"
        class="btn btn-primary"
        :disabled="pw.busy.value || !current"
      >
        Change password
      </button>
    </form>
  </div>
</template>
