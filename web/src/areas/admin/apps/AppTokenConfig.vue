<script setup lang="ts">
import { computed, ref, watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useApplicationStore } from '@/stores/application'
import type { SigningAlg, TokenFormat } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { formatDuration } from '@/lib/format'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'

// Server caps (docs/api/management.md): access 300 s – 24 h; refresh up to 90 d (public: 7 d).
const ACCESS_MIN_MIN = 5
const ACCESS_MAX_MIN = 1440
const REFRESH_MAX_HOURS = { confidential: 90 * 24, public: 7 * 24 }

const store = useApplicationStore()
const { app, canEdit, canEditConfig } = storeToRefs(store)
const format = ref<TokenFormat>('jwt')
const alg = ref<SigningAlg>('RS256')
const accessMinutes = ref(60)
const refreshHours = ref(24)
// The inputs show rounded units; remember what was shown so a lifetime the admin didn't touch
// (e.g. 3700 s shown as 62 min) is never rewritten by the rounding.
const shown = { access: 60, refresh: 24 }
const saved = ref(false)
const { busy, error, run } = useAction()

const refreshMax = computed(() => REFRESH_MAX_HOURS[app.value?.client_type ?? 'confidential'])

watchEffect(() => {
  if (!app.value) return
  format.value = app.value.access_token_format
  alg.value = app.value.signing_alg
  shown.access = accessMinutes.value = Math.round(app.value.access_token_ttl_secs / 60)
  shown.refresh = refreshHours.value = Math.round(app.value.refresh_token_ttl_secs / 3600)
})

async function save() {
  saved.value = false
  const ok = await run(() =>
    store.update({
      access_token_format: format.value,
      signing_alg: alg.value,
      ...(accessMinutes.value !== shown.access
        ? { access_token_ttl_secs: accessMinutes.value * 60 }
        : {}),
      ...(refreshHours.value !== shown.refresh
        ? { refresh_token_ttl_secs: refreshHours.value * 3600 }
        : {}),
    }),
  )
  saved.value = !!ok
}
</script>

<template>
  <form
    v-if="app"
    class="card max-w-2xl space-y-5"
    @submit.prevent="save"
    @input="saved = false"
  >
    <p class="muted text-sm">
      Format, algorithm and access-token lifetime apply to tokens issued <em>for</em> this app as
      an API. The signing algorithm also signs ID tokens issued <em>to</em> it.
    </p>
    <div class="grid gap-4 sm:grid-cols-2">
      <div>
        <label
          class="label"
          for="tc-format"
        >Access token format</label>
        <select
          id="tc-format"
          v-model="format"
          class="input"
          :disabled="!canEditConfig"
        >
          <option value="jwt">
            JWT (self-contained)
          </option>
          <option value="opaque">
            Opaque (introspection)
          </option>
        </select>
      </div>
      <div>
        <label
          class="label"
          for="tc-alg"
        >Signing algorithm</label>
        <select
          id="tc-alg"
          v-model="alg"
          class="input"
          :disabled="!canEditConfig"
        >
          <option value="RS256">
            RS256
          </option>
          <option value="ES256">
            ES256
          </option>
        </select>
      </div>
      <div>
        <label
          class="label"
          for="tc-access"
        >Access token lifetime (minutes)</label>
        <input
          id="tc-access"
          v-model.number="accessMinutes"
          class="input"
          type="number"
          :min="ACCESS_MIN_MIN"
          :max="ACCESS_MAX_MIN"
          :disabled="!canEdit"
          required
        >
        <p class="hint">
          {{ ACCESS_MIN_MIN }}–{{ ACCESS_MAX_MIN }} minutes (now
          {{ formatDuration(app.access_token_ttl_secs) }}).
        </p>
      </div>
      <div>
        <label
          class="label"
          for="tc-refresh"
        >Refresh token lifetime (hours)</label>
        <input
          id="tc-refresh"
          v-model.number="refreshHours"
          class="input"
          type="number"
          min="1"
          :max="refreshMax"
          :disabled="!canEdit"
          required
        >
        <p class="hint">
          Up to {{ formatDuration(refreshMax * 3600) }} for {{ app.client_type }} clients (now
          {{ formatDuration(app.refresh_token_ttl_secs) }}).
        </p>
      </div>
    </div>
    <ErrorAlert :error="error" />
    <StatusNote :message="saved ? 'Saved.' : null" />
    <button
      v-if="canEdit"
      type="submit"
      class="btn btn-primary"
      :disabled="busy"
    >
      Save
    </button>
  </form>
</template>
