<script setup lang="ts">
import { ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { users, type CreatedUser } from '@/api/directory'
import type { User } from '@/api/types'
import { usePagedList } from '@/composables/usePagedList'
import { formatDate } from '@/lib/format'
import PageHeader from '@/components/PageHeader.vue'
import ListShell from '@/components/ListShell.vue'
import StatusNote from '@/components/StatusNote.vue'
import SecretOnceDialog from '@/components/SecretOnceDialog.vue'
import CreateUserDialog from './CreateUserDialog.vue'

const { canWriteUsers } = storeToRefs(useAuthStore())
const list = usePagedList<User>(users.list)
const creating = ref(false)
const oneTime = ref<string[] | null>(null)
const invited = ref<string | null>(null)

function startCreate() {
  invited.value = null
  creating.value = true
}

function created(res: CreatedUser) {
  creating.value = false
  invited.value = res.invite_sent ? `Invitation sent to ${res.user.email}.` : null
  if (res.one_time_password) oneTime.value = [res.one_time_password]
  list.reload()
}
</script>

<template>
  <section>
    <PageHeader
      title="Users"
      description="Members of this directory."
    >
      <template
        v-if="canWriteUsers"
        #actions
      >
        <button
          type="button"
          class="btn btn-primary"
          @click="startCreate"
        >
          New user
        </button>
      </template>
    </PageHeader>
    <StatusNote
      :message="invited"
      class="mb-2"
    />
    <ListShell
      :list="list"
      search-label="Search by name or email"
      empty="No users found."
    >
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              Display name
            </th>
            <th scope="col">
              Email
            </th>
            <th scope="col">
              Status
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
            v-for="u in list.items"
            :key="u.id"
          >
            <td>
              <RouterLink
                :to="{ name: 'admin-user', params: { id: u.id } }"
                class="btn-link"
              >
                {{ u.display_name || '(no name)' }}
              </RouterLink>
            </td>
            <td class="break-all">
              {{ u.email }}
            </td>
            <td>
              <span
                v-if="u.disabled"
                class="badge"
              >Disabled</span>
              <span v-else>Enabled</span>
            </td>
            <td class="hidden md:table-cell">
              {{ formatDate(u.created_at) }}
            </td>
          </tr>
        </tbody>
      </table>
    </ListShell>
    <CreateUserDialog
      :open="creating"
      @close="creating = false"
      @created="created"
    />
    <SecretOnceDialog
      title="Temporary password"
      description="Give this password to the user. They must change it when they first sign in."
      :values="oneTime"
      @close="oneTime = null"
    />
  </section>
</template>
