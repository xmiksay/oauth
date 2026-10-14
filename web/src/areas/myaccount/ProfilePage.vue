<script setup lang="ts">
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { me as meApi } from '@/api/me'
import { ROLE_LABELS } from '@/api/types'
import { useAction } from '@/composables/useAction'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'
import EmailSection from './EmailSection.vue'
import PasswordSection from './PasswordSection.vue'

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

    <PasswordSection />
  </div>
</template>
