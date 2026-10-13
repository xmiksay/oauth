<script setup lang="ts">
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { appRoles } from '@/api/applications'
import { roleAssignments } from '@/api/access'
import type { AppRole, AppRoleAssignment } from '@/api/types'
import { usePagedList } from '@/composables/usePagedList'
import { usePrincipalNames } from '@/composables/usePrincipalNames'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import PageHeader from '@/components/PageHeader.vue'
import ListShell from '@/components/ListShell.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import PrincipalPicker, { type Picked } from '@/components/PrincipalPicker.vue'
import AssignRoleForm from './AssignRoleForm.vue'

const { canWriteApps } = storeToRefs(useAuthStore())
const resource = ref<Picked | null>(null)
const roles = ref<AppRole[]>([])
const { name } = usePrincipalNames()
const { error, run } = useAction()

const list = usePagedList<AppRoleAssignment>((q) =>
  roleAssignments.list({ ...q, resource_application_id: resource.value?.id }),
)

const roleName = computed(() => {
  const byId = new Map(roles.value.map((r) => [r.id, r.display_name || r.value]))
  return (id: string) => byId.get(id) ?? id
})

async function pick(p: Picked) {
  resource.value = p
  // The list loads when its ListShell (keyed by the resource) mounts.
  roles.value = (await run(() => appRoles.list(p.id)))?.items ?? []
}

function unassign(assignmentId: string) {
  return roleAssignments.remove(assignmentId)
}
</script>

<template>
  <section>
    <PageHeader
      title="Role assignments"
      description="Assign users, groups and applications to the app roles an application defines."
    />
    <div class="card mb-5 max-w-xl">
      <PrincipalPicker
        v-if="!resource"
        kind="application"
        label="Application (the API defining the roles)"
        @select="pick"
      />
      <p
        v-else
        class="text-sm"
      >
        <strong>{{ resource.label }}</strong> <span class="mono muted">{{ resource.detail }}</span>
        <button
          type="button"
          class="btn-link ml-2"
          @click="resource = null"
        >
          Change
        </button>
      </p>
      <ErrorAlert
        class="mt-2"
        :error="error"
      />
    </div>
    <template v-if="resource">
      <p
        v-if="!roles.length"
        class="card muted text-sm"
      >
        This application defines no app roles. Add some under App registrations → App roles.
      </p>
      <template v-else>
        <AssignRoleForm
          v-if="canWriteApps"
          :roles="roles"
          class="mb-5"
          @assigned="list.reload()"
        />
        <ListShell
          :key="resource.id"
          :list="list"
          empty="No assignments yet."
        >
          <table class="table">
            <thead>
              <tr>
                <th scope="col">
                  Principal
                </th>
                <th scope="col">
                  Type
                </th>
                <th scope="col">
                  Role
                </th>
                <th
                  scope="col"
                  class="hidden sm:table-cell"
                >
                  Assigned
                </th>
                <th scope="col">
                  <span class="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="a in list.items"
                :key="a.id"
              >
                <td>{{ name(a.principal_type, a.principal_id) }}</td>
                <td>{{ a.principal_type }}</td>
                <td>{{ roleName(a.app_role_id) }}</td>
                <td class="hidden sm:table-cell">
                  {{ formatDate(a.created_at) }}
                </td>
                <td class="text-right">
                  <ConfirmButton
                    v-if="canWriteApps"
                    label="Remove"
                    title="Remove assignment?"
                    message="The principal loses this role in newly issued tokens."
                    danger
                    :action="() => unassign(a.id)"
                    @done="list.reload()"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </ListShell>
      </template>
    </template>
  </section>
</template>
