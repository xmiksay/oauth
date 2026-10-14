<script setup lang="ts">
import { ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { directoryRoles } from '@/api/directory'
import {
  DIRECTORY_ROLES,
  ROLE_LABELS,
  type DirectoryRole,
  type DirectoryRoleAssignment,
} from '@/api/types'
import { usePagedList } from '@/composables/usePagedList'
import { usePrincipalNames } from '@/composables/usePrincipalNames'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import PageHeader from '@/components/PageHeader.vue'
import ListShell from '@/components/ListShell.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import PrincipalPicker, { type Picked } from '@/components/PrincipalPicker.vue'

const DESCRIPTIONS: Record<DirectoryRole, string> = {
  GlobalAdmin: 'Everything, including directory roles and management-API access.',
  UserAdmin: 'Users, groups and memberships (not administrators).',
  ApplicationAdmin: 'App registrations, secrets, permissions, assignments and consents.',
}

const { isGlobalAdmin } = storeToRefs(useAuthStore())
const filter = ref<DirectoryRole | ''>('')
const list = usePagedList<DirectoryRoleAssignment>((q) =>
  directoryRoles.list({ ...q, ...(filter.value ? { role: filter.value } : {}) }),
)
watch(filter, () => list.reload())
const { name } = usePrincipalNames()

const role = ref<DirectoryRole>('UserAdmin')
const user = ref<Picked | null>(null)
const { busy, error, run } = useAction()

async function assign() {
  const u = user.value
  if (!u) return
  if (await run(() => directoryRoles.assign(u.id, role.value))) {
    user.value = null
    await list.reload()
  }
}

function unassign(assignmentId: string) {
  return directoryRoles.unassign(assignmentId)
}
</script>

<template>
  <section>
    <PageHeader
      title="Directory roles"
      description="Administrative roles in this directory. Only Global Administrators can change them."
    />
    <dl class="mb-5 grid gap-2 sm:grid-cols-3">
      <div
        v-for="r in DIRECTORY_ROLES"
        :key="r"
        class="card sm:p-4"
      >
        <dt class="text-sm font-semibold">
          {{ ROLE_LABELS[r] }}
        </dt>
        <dd class="muted mt-1 text-xs">
          {{ DESCRIPTIONS[r] }}
        </dd>
      </div>
    </dl>
    <form
      v-if="isGlobalAdmin"
      class="card mb-5 grid gap-3 sm:grid-cols-[2fr_1fr_auto] sm:items-end"
      @submit.prevent="assign"
    >
      <div>
        <PrincipalPicker
          v-if="!user"
          kind="user"
          label="User"
          @select="user = $event"
        />
        <p
          v-else
          class="text-sm"
        >
          <span class="label">User</span>
          {{ user.label }}
          <button
            type="button"
            class="btn-link ml-1"
            @click="user = null"
          >
            Change
          </button>
        </p>
      </div>
      <div>
        <label
          class="label"
          for="dr-role"
        >Role</label>
        <select
          id="dr-role"
          v-model="role"
          class="input"
        >
          <option
            v-for="r in DIRECTORY_ROLES"
            :key="r"
            :value="r"
          >
            {{ ROLE_LABELS[r] }}
          </option>
        </select>
      </div>
      <button
        type="submit"
        class="btn btn-primary"
        :disabled="busy || !user"
      >
        Assign
      </button>
      <ErrorAlert
        class="sm:col-span-3"
        :error="error"
      />
    </form>
    <div class="mb-3 max-w-xs">
      <label
        class="label"
        for="dr-filter"
      >Show</label>
      <select
        id="dr-filter"
        v-model="filter"
        class="input"
      >
        <option value="">
          All roles
        </option>
        <option
          v-for="r in DIRECTORY_ROLES"
          :key="r"
          :value="r"
        >
          {{ ROLE_LABELS[r] }}
        </option>
      </select>
    </div>
    <ListShell
      :list="list"
      empty="No role assignments."
    >
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              User
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
            <td>
              <RouterLink
                :to="{ name: 'admin-user', params: { id: a.user_id } }"
                class="btn-link"
              >
                {{ name('user', a.user_id) }}
              </RouterLink>
            </td>
            <td>{{ ROLE_LABELS[a.role] }}</td>
            <td class="hidden sm:table-cell">
              {{ formatDate(a.created_at) }}
            </td>
            <td class="text-right">
              <ConfirmButton
                v-if="isGlobalAdmin"
                label="Remove"
                title="Remove role assignment?"
                :message="`Remove ${ROLE_LABELS[a.role]} from this user? The last enabled Global Administrator can't be removed.`"
                danger
                :action="() => unassign(a.id)"
                @done="list.reload()"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </ListShell>
  </section>
</template>
