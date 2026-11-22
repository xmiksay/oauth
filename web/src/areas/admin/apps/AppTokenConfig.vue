<script setup lang="ts">
import { computed, ref, watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useApplicationStore } from '@/stores/application'
import type {
  AppMfaPolicy,
  GroupsClaimFormat,
  IdTokenGroups,
  SigningAlg,
  TokenFormat,
} from '@/api/types'
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
const groupsClaim = ref<GroupsClaimFormat>('id')
const idTokenGroups = ref<IdTokenGroups>('none')
const mfa = ref<AppMfaPolicy>('inherit')
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
  groupsClaim.value = app.value.groups_claim_format
  idTokenGroups.value = app.value.id_token_groups
  mfa.value = app.value.mfa_policy
  shown.access = accessMinutes.value = Math.round(app.value.access_token_ttl_secs / 60)
  shown.refresh = refreshHours.value = Math.round(app.value.refresh_token_ttl_secs / 3600)
})

async function save() {
  saved.value = false
  const ok = await run(() =>
    store.update({
      access_token_format: format.value,
      signing_alg: alg.value,
      groups_claim_format: groupsClaim.value,
      id_token_groups: idTokenGroups.value,
      mfa_policy: mfa.value,
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
      <div class="sm:col-span-2">
        <label
          class="label"
          for="tc-groups"
        >Groups claim</label>
        <select
          id="tc-groups"
          v-model="groupsClaim"
          class="input"
          :disabled="!canEditConfig"
          aria-describedby="tc-groups-hint"
        >
          <option value="id">
            Group IDs
          </option>
          <option value="name">
            Group names
          </option>
        </select>
        <p
          id="tc-groups-hint"
          class="hint"
        >
          What the <code>groups</code> claim of access tokens for this API, and of ID tokens and
          userinfo issued to this app, lists. Names suit consumers that bind to readable names
          (Kubernetes, Grafana) but change when a group is renamed; IDs never do. Over 200 groups,
          either becomes <code>hasgroups: true</code>.
        </p>
      </div>
      <div class="sm:col-span-2">
        <label
          class="label"
          for="tc-id-groups"
        >Groups in ID token</label>
        <select
          id="tc-id-groups"
          v-model="idTokenGroups"
          class="input"
          :disabled="!canEditConfig"
          aria-describedby="tc-id-groups-hint"
        >
          <option value="none">
            None
          </option>
          <option value="all">
            All of the user's groups
          </option>
          <option value="assigned">
            Groups assigned to this app
          </option>
        </select>
        <p
          id="tc-id-groups-hint"
          class="hint"
        >
          Adds a <code>groups</code> claim to ID tokens and userinfo issued to this app, for
          sign-in clients that authorize by groups (Headlamp, Grafana, ArgoCD). Assigned: only
          groups holding one of this app's roles. The <code>groups</code> scope is accepted but
          doesn't turn this on.
        </p>
      </div>
      <div class="sm:col-span-2">
        <label
          class="label"
          for="tc-mfa"
        >Multi-factor authentication</label>
        <select
          id="tc-mfa"
          v-model="mfa"
          class="input"
          :disabled="!canEdit"
          aria-describedby="tc-mfa-hint"
        >
          <option value="inherit">
            As the directory's setting
          </option>
          <option value="required">
            Required
          </option>
        </select>
        <p
          id="tc-mfa-hint"
          class="hint"
        >
          Required: signing in to this app, or requesting access to it as an API, needs a second
          factor even when the directory leaves MFA optional. An app can't relax the directory's
          setting.
        </p>
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
