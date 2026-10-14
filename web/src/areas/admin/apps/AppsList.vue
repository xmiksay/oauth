<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { applications } from '@/api/applications'
import type { Application, ClientType } from '@/api/types'
import { usePagedList } from '@/composables/usePagedList'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import PageHeader from '@/components/PageHeader.vue'
import ListShell from '@/components/ListShell.vue'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'

const router = useRouter()
const { canWriteApps } = storeToRefs(useAuthStore())
const list = usePagedList<Application>(applications.list)

const creating = ref(false)
const name = ref('')
const clientType = ref<ClientType>('confidential')
const redirectUri = ref('')
const { busy, error, run } = useAction()

function openCreate() {
  name.value = ''
  clientType.value = 'confidential'
  redirectUri.value = ''
  error.value = null
  creating.value = true
}

async function create() {
  const uri = redirectUri.value.trim()
  const app = await run(() =>
    applications.create({
      display_name: name.value.trim(),
      client_type: clientType.value,
      ...(uri ? { redirect_uris: [uri] } : {}),
    }),
  )
  if (app) await router.push({ name: 'admin-app', params: { id: app.id } })
}
</script>

<template>
  <section>
    <PageHeader
      title="App registrations"
      description="Applications that sign users in or expose an API."
    >
      <template
        v-if="canWriteApps"
        #actions
      >
        <button
          type="button"
          class="btn btn-primary"
          @click="openCreate"
        >
          New registration
        </button>
      </template>
    </PageHeader>
    <ListShell
      :list="list"
      search-label="Search by name or client ID"
      empty="No applications found."
    >
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              Display name
            </th>
            <th scope="col">
              Client ID
            </th>
            <th
              scope="col"
              class="hidden sm:table-cell"
            >
              Type
            </th>
            <th
              scope="col"
              class="hidden md:table-cell"
            >
              Created
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="a in list.items"
            :key="a.id"
          >
            <td>
              <RouterLink
                :to="{ name: 'admin-app', params: { id: a.id } }"
                class="btn-link"
              >
                {{ a.display_name }}
              </RouterLink>
              <span
                v-if="a.builtin"
                class="badge ml-1"
              >Built-in</span>
            </td>
            <td class="mono">
              {{ a.client_id }}
            </td>
            <td class="hidden sm:table-cell">
              {{ a.client_type }}
            </td>
            <td class="hidden md:table-cell">
              {{ formatDate(a.created_at) }}
            </td>
          </tr>
        </tbody>
      </table>
    </ListShell>
    <ModalDialog
      :open="creating"
      title="Register an application"
      @close="creating = false"
    >
      <form
        id="create-app"
        class="space-y-4"
        @submit.prevent="create"
      >
        <div>
          <label
            class="label"
            for="ca-name"
          >Name</label>
          <input
            id="ca-name"
            v-model="name"
            class="input"
            required
          >
        </div>
        <fieldset>
          <legend class="label">
            Client type
          </legend>
          <label class="flex items-start gap-2 text-sm">
            <input
              v-model="clientType"
              type="radio"
              value="confidential"
              class="mt-1"
            >
            <span>Confidential — a server-side app that can keep a client secret</span>
          </label>
          <label class="mt-1 flex items-start gap-2 text-sm">
            <input
              v-model="clientType"
              type="radio"
              value="public"
              class="mt-1"
            >
            <span>Public — a SPA, mobile or desktop app (PKCE, no secret)</span>
          </label>
        </fieldset>
        <div>
          <label
            class="label"
            for="ca-redirect"
          >Redirect URI (optional)</label>
          <input
            id="ca-redirect"
            v-model="redirectUri"
            class="input"
            type="url"
            placeholder="https://app.example.com/callback"
          >
          <p class="hint">
            https://, or http://127.0.0.1 / http://[::1] for local apps.
          </p>
        </div>
        <ErrorAlert :error="error" />
      </form>
      <template #actions>
        <button
          type="button"
          class="btn"
          @click="creating = false"
        >
          Cancel
        </button>
        <button
          type="submit"
          form="create-app"
          class="btn btn-primary"
          :disabled="busy"
        >
          Register
        </button>
      </template>
    </ModalDialog>
  </section>
</template>
