<script setup lang="ts">
import { ref, watchEffect } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useApplicationStore } from '@/stores/application'
import { applications } from '@/api/applications'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import CopyButton from '@/components/CopyButton.vue'

const router = useRouter()
const store = useApplicationStore()
const { app, canEdit, canEditConfig } = storeToRefs(store)
const name = ref('')
const { busy, error, run } = useAction()

watchEffect(() => {
  name.value = app.value?.display_name ?? ''
})

// The tenant is this host, so its origin is the issuer.
const issuer = window.location.origin
const endpoints = [
  ['OpenID Connect metadata', `${issuer}/.well-known/openid-configuration`],
  ['Authorization', `${issuer}/oauth2/authorize`],
  ['Token', `${issuer}/oauth2/token`],
  ['Issuer', issuer],
]

async function save() {
  await run(() => store.update({ display_name: name.value.trim() }))
}

async function remove() {
  if (!app.value) return
  await applications.remove(app.value.id)
  await router.replace({ name: 'admin-apps' })
}
</script>

<template>
  <div
    v-if="app"
    class="grid gap-4 xl:grid-cols-2"
  >
    <div class="card space-y-4">
      <h2 class="font-semibold">
        Essentials
      </h2>
      <form
        class="flex flex-wrap items-end gap-2"
        @submit.prevent="save"
      >
        <div class="min-w-0 flex-1">
          <label
            class="label"
            for="ao-name"
          >Display name</label>
          <input
            id="ao-name"
            v-model="name"
            class="input"
            :disabled="!canEdit"
            required
          >
        </div>
        <button
          v-if="canEdit"
          type="submit"
          class="btn btn-primary"
          :disabled="busy || name.trim() === app.display_name"
        >
          Save
        </button>
      </form>
      <ErrorAlert :error="error" />
      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
        <dt class="muted">
          Client ID
        </dt>
        <dd class="mono">
          {{ app.client_id }}
        </dd>
        <dt class="muted">
          Object ID
        </dt>
        <dd class="mono">
          {{ app.id }}
        </dd>
        <dt class="muted">
          Client type
        </dt>
        <dd>{{ app.client_type }}</dd>
        <dt class="muted">
          Application ID URI
        </dt>
        <dd class="mono">
          {{ app.audience }}
        </dd>
        <dt class="muted">
          Created
        </dt>
        <dd>{{ formatDate(app.created_at) }}</dd>
      </dl>
      <ConfirmButton
        v-if="canEditConfig"
        label="Delete application"
        title="Delete application?"
        :message="`${app.display_name} and its secrets, scopes, roles, permissions, assignments and consents are deleted. Apps using it stop working.`"
        danger
        :action="remove"
      />
    </div>
    <div class="card">
      <h2 class="font-semibold">
        Endpoints
      </h2>
      <ul class="mt-3 space-y-3">
        <li
          v-for="[label, url] in endpoints"
          :key="label"
          class="text-sm"
        >
          <span class="muted block">{{ label }}</span>
          <span class="flex items-center gap-2">
            <span class="mono min-w-0 flex-1">{{ url }}</span>
            <CopyButton
              :text="url ?? ''"
              label="Copy"
            />
          </span>
        </li>
      </ul>
    </div>
  </div>
</template>
