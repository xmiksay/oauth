<script setup lang="ts">
import { onMounted, ref, watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useApplicationStore } from '@/stores/application'
import { scopes as scopesApi } from '@/api/applications'
import type { Scope } from '@/api/types'
import { useAction } from '@/composables/useAction'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import EditScopeDialog from './EditScopeDialog.vue'

const store = useApplicationStore()
const { app, canEditConfig } = storeToRefs(store)
const uri = ref('')
const items = ref<Scope[]>([])
const value = ref('')
const description = ref('')
const adminOnly = ref(false)
const editing = ref<Scope | null>(null)
const uriAction = useAction()
const listAction = useAction()
const addAction = useAction()

watchEffect(() => {
  uri.value = app.value?.identifier_uri ?? ''
})

async function load() {
  if (!app.value) return
  const id = app.value.id
  const res = await listAction.run(() => scopesApi.list(id))
  if (res) items.value = res.items
}

onMounted(load)

async function saveUri() {
  const next = uri.value.trim()
  await uriAction.run(() => store.update({ identifier_uri: next || null }))
}

async function add() {
  if (!app.value) return
  const id = app.value.id
  const created = await addAction.run(() =>
    scopesApi.create(id, {
      value: value.value.trim(),
      description: description.value.trim(),
      admin_consent_required: adminOnly.value,
    }),
  )
  if (!created) return
  value.value = ''
  description.value = ''
  adminOnly.value = false
  await load()
}

async function edited() {
  editing.value = null
  await load()
}

async function remove(scopeId: string) {
  if (app.value) await scopesApi.remove(app.value.id, scopeId)
}
</script>

<template>
  <div
    v-if="app"
    class="space-y-4"
  >
    <form
      class="card space-y-3"
      @submit.prevent="saveUri"
    >
      <label
        class="label"
        for="ex-uri"
      >Application ID URI</label>
      <div class="flex flex-wrap gap-2">
        <input
          id="ex-uri"
          v-model="uri"
          class="input min-w-0 flex-1 font-mono"
          :placeholder="`api://${app.client_id}`"
          :disabled="!canEditConfig"
        >
        <template v-if="canEditConfig">
          <button
            type="button"
            class="btn"
            @click="uri = `api://${app.client_id}`"
          >
            Use default
          </button>
          <button
            type="submit"
            class="btn btn-primary"
            :disabled="uriAction.busy.value"
          >
            Save
          </button>
        </template>
      </div>
      <p class="hint">
        <span class="mono">api://{{ app.client_id }}</span> or an https:// URI without query or
        fragment. Scopes are requested as <span class="mono">{{ app.audience }}/&lt;scope&gt;</span>.
      </p>
      <ErrorAlert :error="uriAction.error.value" />
    </form>

    <div class="card space-y-3">
      <h2 class="font-semibold">
        Scopes defined by this API
      </h2>
      <ErrorAlert :error="listAction.error.value" />
      <div class="overflow-x-auto">
        <table
          v-if="items.length"
          class="table"
        >
          <thead>
            <tr>
              <th scope="col">
                Scope
              </th>
              <th scope="col">
                Description
              </th>
              <th scope="col">
                Who can consent
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
              <td class="mono">
                {{ s.value }}
              </td>
              <td>{{ s.description }}</td>
              <td>
                {{ s.admin_consent_required ? 'Admins only' : 'Admins and users' }}
              </td>
              <td class="space-x-1 text-right whitespace-nowrap">
                <button
                  v-if="canEditConfig"
                  type="button"
                  class="btn"
                  @click="editing = s"
                >
                  Edit
                </button>
                <ConfirmButton
                  v-if="canEditConfig"
                  label="Delete"
                  title="Delete scope?"
                  :message="`${s.value} is removed from consent grants and required permissions; refresh tokens holding it are revoked.`"
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
          class="muted text-sm"
        >
          No scopes yet.
        </p>
      </div>
      <form
        v-if="canEditConfig"
        class="grid gap-3 border-t border-neutral-200 pt-4 sm:grid-cols-[1fr_2fr_auto_auto] sm:items-end dark:border-neutral-800"
        @submit.prevent="add"
      >
        <div>
          <label
            class="label"
            for="ex-value"
          >Scope name</label>
          <input
            id="ex-value"
            v-model="value"
            class="input font-mono"
            placeholder="Orders.Read"
            required
          >
        </div>
        <div>
          <label
            class="label"
            for="ex-desc"
          >Description shown on consent</label>
          <input
            id="ex-desc"
            v-model="description"
            class="input"
          >
        </div>
        <label class="flex items-center gap-2 pb-2 text-sm">
          <input
            v-model="adminOnly"
            type="checkbox"
          >
          Admin consent only
        </label>
        <button
          type="submit"
          class="btn btn-primary"
          :disabled="addAction.busy.value"
        >
          Add scope
        </button>
        <ErrorAlert
          class="sm:col-span-4"
          :error="addAction.error.value"
        />
      </form>
    </div>
    <EditScopeDialog
      :app-id="app.id"
      :scope="editing"
      @close="editing = null"
      @saved="edited"
    />
  </div>
</template>
