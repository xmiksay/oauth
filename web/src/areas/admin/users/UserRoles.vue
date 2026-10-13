<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { directoryRoles } from '@/api/directory'
import {
  DIRECTORY_ROLES,
  ROLE_LABELS,
  type DirectoryRole,
  type DirectoryRoleAssignment,
} from '@/api/types'
import { useAction } from '@/composables/useAction'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'

const props = defineProps<{ userId: string }>()
const { isGlobalAdmin } = storeToRefs(useAuthStore())

const assignments = ref<DirectoryRoleAssignment[]>([])
const role = ref<DirectoryRole>('UserAdmin')
const { busy, error, run } = useAction()

async function load() {
  const res = await run(() => directoryRoles.list({ user_id: props.userId, limit: 200 }))
  if (res) assignments.value = res.items
}

async function assign() {
  if (await run(() => directoryRoles.assign(props.userId, role.value))) await load()
}

onMounted(load)

function unassign(assignmentId: string) {
  return directoryRoles.unassign(assignmentId)
}
</script>

<template>
  <div class="card">
    <h2 class="font-semibold">
      Directory roles
    </h2>
    <ul
      v-if="assignments.length"
      class="mt-3 divide-y divide-neutral-200 dark:divide-neutral-800"
    >
      <li
        v-for="a in assignments"
        :key="a.id"
        class="flex items-center justify-between gap-2 py-2 text-sm"
      >
        <span>{{ ROLE_LABELS[a.role] }}</span>
        <ConfirmButton
          v-if="isGlobalAdmin"
          label="Remove"
          title="Remove role?"
          :message="`Remove the ${ROLE_LABELS[a.role]} role from this user?`"
          danger
          :action="() => unassign(a.id)"
          @done="load"
        />
      </li>
    </ul>
    <p
      v-else
      class="muted mt-3 text-sm"
    >
      No directory roles.
    </p>
    <form
      v-if="isGlobalAdmin"
      class="mt-4 flex flex-wrap items-end gap-2"
      @submit.prevent="assign"
    >
      <div>
        <label
          class="label"
          for="ur-role"
        >Assign role</label>
        <select
          id="ur-role"
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
        class="btn"
        :disabled="busy"
      >
        Assign
      </button>
    </form>
    <ErrorAlert
      class="mt-3"
      :error="error"
    />
  </div>
</template>
