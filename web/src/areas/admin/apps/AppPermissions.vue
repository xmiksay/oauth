<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useApplicationStore } from '@/stores/application'
import { requiredPermissions } from '@/api/applications'
import { consents, roleAssignments } from '@/api/access'
import { allPages } from '@/api/management'
import type { AppRoleAssignment, ConsentGrant, RequiredPermission } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { usePrincipalNames } from '@/composables/usePrincipalNames'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import AddPermissionDialog from './AddPermissionDialog.vue'

const { app, canEditConfig } = storeToRefs(useApplicationStore())
const perms = ref<RequiredPermission[]>([])
const grants = ref<ConsentGrant[]>([])
const assignments = ref<AppRoleAssignment[]>([])
const adding = ref(false)
const loader = useAction()
const { name } = usePrincipalNames()

async function load() {
  if (!app.value) return
  const id = app.value.id
  const res = await loader.run(() =>
    Promise.all([
      requiredPermissions.list(id),
      allPages((q) => consents.list({ ...q, client_application_id: id })),
      allPages((q) => roleAssignments.list({ ...q, principal_id: id })),
    ]),
  )
  if (!res) return
  perms.value = res[0].items
  grants.value = res[1].filter((g) => g.user_id === null)
  assignments.value = res[2]
}

onMounted(load)

/** Required permissions grouped by resource app. */
const byResource = computed(() => {
  const groups = new Map<string, { id: string; clientId: string; items: RequiredPermission[] }>()
  for (const p of perms.value) {
    const g = groups.get(p.resource_application_id) ?? {
      id: p.resource_application_id,
      clientId: p.resource_client_id,
      items: [],
    }
    g.items.push(p)
    groups.set(p.resource_application_id, g)
  }
  return [...groups.values()]
})

function granted(p: RequiredPermission): boolean {
  if (p.type === 'application') return assignments.value.some((a) => a.app_role_id === p.permission_id)
  return grants.value.some(
    (g) => g.resource_application_id === p.resource_application_id && g.scopes.includes(p.value),
  )
}

const allGranted = computed(() => perms.value.every(granted))

async function grantAll() {
  if (!app.value) return
  for (const r of byResource.value) {
    await consents.grant({ client_application_id: app.value.id, resource_application_id: r.id })
  }
}

async function remove(permissionId: string) {
  if (app.value) await requiredPermissions.remove(app.value.id, permissionId)
}
</script>

<template>
  <div
    v-if="app"
    class="space-y-4"
  >
    <div class="flex flex-wrap items-center gap-2">
      <p class="muted min-w-0 flex-1 text-sm">
        Permissions this app requests from APIs. "Grant admin consent" approves them for every
        user of the directory (delegated) or assigns the app roles (application).
      </p>
      <button
        v-if="canEditConfig"
        type="button"
        class="btn"
        @click="adding = true"
      >
        Add a permission
      </button>
      <ConfirmButton
        v-if="canEditConfig && perms.length"
        label="Grant admin consent"
        title="Grant admin consent?"
        :message="`Grant every listed permission for all users of this directory to ${app.display_name}?`"
        confirm-label="Grant"
        :disabled="allGranted"
        :action="grantAll"
        @done="load"
      />
    </div>
    <ErrorAlert :error="loader.error.value" />
    <p
      v-if="!perms.length && !loader.busy.value"
      class="card muted text-sm"
    >
      No API permissions requested.
    </p>
    <div
      v-for="r in byResource"
      :key="r.id"
      class="card overflow-x-auto p-0 sm:p-0"
    >
      <h2 class="px-3 pt-3 text-sm font-semibold">
        {{ name('application', r.id, r.clientId) }} <span class="mono muted font-normal">{{ r.clientId }}</span>
      </h2>
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              Permission
            </th>
            <th scope="col">
              Type
            </th>
            <th scope="col">
              Status
            </th>
            <th scope="col">
              <span class="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="p in r.items"
            :key="p.id"
          >
            <td class="mono">
              {{ p.value }}
            </td>
            <td>{{ p.type }}</td>
            <td>
              <span
                v-if="granted(p)"
                class="text-green-700 dark:text-green-400"
              >Granted for the directory</span>
              <span
                v-else
                class="muted"
              >Not granted</span>
            </td>
            <td class="text-right">
              <ConfirmButton
                v-if="canEditConfig"
                label="Remove"
                title="Remove permission?"
                :message="`Stop requesting ${p.value}? Existing consent grants are not changed.`"
                danger
                :action="() => remove(p.id)"
                @done="load"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <AddPermissionDialog
      :open="adding"
      :app-id="app.id"
      @close="adding = false"
      @added="adding = false; load()"
      @changed="load"
    />
  </div>
</template>
