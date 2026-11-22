<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useApplicationStore } from '@/stores/application'
import { secrets } from '@/api/applications'
import { settings } from '@/api/access'
import type { ClientSecret, SecretCreate } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import SecretOnceDialog from '@/components/SecretOnceDialog.vue'

const EXPIRY_DAYS = [30, 90, 180, 365, 730]
/** `days` value for "never expires". */
const NEVER = 0

const { app, canEditConfig } = storeToRefs(useApplicationStore())
const items = ref<ClientSecret[]>([])
const description = ref('')
const days = ref(180)
const created = ref<string[] | null>(null)
const allowNever = ref(false)
const loader = useAction()
const creator = useAction()

async function load() {
  if (!app.value || app.value.client_type === 'public') return
  const id = app.value.id
  const res = await loader.run(() => secrets.list(id))
  if (res) items.value = res.items
}

async function loadPolicy() {
  // Without the setting (e.g. a failed read) the option simply isn't offered.
  const t = await settings.get().catch(() => null)
  allowNever.value = t?.allow_non_expiring_secrets ?? false
}

onMounted(() => Promise.all([load(), loadPolicy()]))

async function create() {
  if (!app.value) return
  const id = app.value.id
  const desc = description.value.trim()
  const body: SecretCreate =
    days.value === NEVER ? { never_expires: true } : { expires_in_days: days.value }
  if (desc) body.description = desc
  const res = await creator.run(() => secrets.create(id, body))
  if (!res) return
  if (res.secret) created.value = [res.secret]
  description.value = ''
  await load()
}

async function remove(secretId: string) {
  if (app.value) await secrets.remove(app.value.id, secretId)
}

const expired = (s: ClientSecret) =>
  s.expires_at !== null && new Date(s.expires_at).getTime() < Date.now()
</script>

<template>
  <div
    v-if="app"
    class="space-y-4"
  >
    <p
      v-if="app.client_type === 'public'"
      class="card muted text-sm"
    >
      Public clients can't hold secrets — they use PKCE instead.
    </p>
    <template v-else>
      <form
        v-if="canEditConfig"
        class="card flex flex-wrap items-end gap-3"
        @submit.prevent="create"
      >
        <div class="min-w-48 flex-1">
          <label
            class="label"
            for="as-desc"
          >Description</label>
          <input
            id="as-desc"
            v-model="description"
            class="input"
            maxlength="200"
          >
        </div>
        <div>
          <label
            class="label"
            for="as-days"
          >Expires</label>
          <select
            id="as-days"
            v-model.number="days"
            class="input"
          >
            <option
              v-for="d in EXPIRY_DAYS"
              :key="d"
              :value="d"
            >
              {{ d }} days
            </option>
            <option
              v-if="allowNever"
              :value="NEVER"
            >
              Never
            </option>
          </select>
        </div>
        <button
          type="submit"
          class="btn btn-primary"
          :disabled="creator.busy.value"
        >
          New client secret
        </button>
        <ErrorAlert
          class="w-full"
          :error="creator.error.value"
        />
      </form>
      <ErrorAlert :error="loader.error.value" />
      <div class="card overflow-x-auto p-0 sm:p-0">
        <table
          v-if="items.length"
          class="table"
        >
          <thead>
            <tr>
              <th scope="col">
                Description
              </th>
              <th scope="col">
                Value
              </th>
              <th scope="col">
                Expires
              </th>
              <th scope="col">
                <span class="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="s in items"
              :key="s.id"
            >
              <td>{{ s.description || '—' }}</td>
              <td class="mono">
                {{ s.hint }}…
              </td>
              <td>
                {{ s.never_expires ? 'Never' : formatDate(s.expires_at) }}
                <span
                  v-if="expired(s)"
                  class="badge ml-1"
                >Expired</span>
              </td>
              <td class="text-right">
                <ConfirmButton
                  v-if="canEditConfig"
                  label="Delete"
                  title="Delete client secret?"
                  message="Apps using this secret can no longer authenticate."
                  danger
                  :action="() => remove(s.id)"
                  @done="load"
                />
              </td>
            </tr>
          </tbody>
        </table>
        <p
          v-else
          class="muted p-4 text-sm"
        >
          No client secrets.
        </p>
      </div>
    </template>
    <SecretOnceDialog
      title="Client secret"
      description="Store the value in your app's configuration (e.g. a secret store)."
      :values="created"
      @close="created = null"
    />
  </div>
</template>
