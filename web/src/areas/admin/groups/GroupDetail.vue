<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { groups } from '@/api/directory'
import type { Group, User } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { usePagedList } from '@/composables/usePagedList'
import PageHeader from '@/components/PageHeader.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import ListShell from '@/components/ListShell.vue'
import PrincipalPicker, { type Picked } from '@/components/PrincipalPicker.vue'

const route = useRoute()
const router = useRouter()
const tenant = route.params.tenant
const id = String(route.params.id)
const { canWriteUsers } = storeToRefs(useAuthStore())

const group = ref<Group | null>(null)
const name = ref('')
const description = ref('')
const loader = useAction()
const saver = useAction()
const members = usePagedList<User>((q) => groups.members(id, q))

async function load() {
  const g = await loader.run(() => groups.get(id))
  if (!g) return
  group.value = g
  name.value = g.display_name
  description.value = g.description ?? ''
}

onMounted(load)

async function save() {
  const body = { display_name: name.value.trim(), description: description.value.trim() }
  if (await saver.run(() => groups.update(id, body))) await load()
}

async function addMember(p: Picked) {
  if (await saver.run(() => groups.addMember(id, p.id).then(() => true))) await members.reload()
}

async function remove() {
  await groups.remove(id)
  await router.replace({ name: 'admin-groups', params: { tenant } })
}

function removeMember(userId: string) {
  return groups.removeMember(id, userId)
}
</script>

<template>
  <section>
    <PageHeader :title="group?.display_name ?? 'Group'">
      <template #breadcrumb>
        <RouterLink
          :to="{ name: 'admin-groups', params: { tenant } }"
          class="btn-link"
        >
          Groups
        </RouterLink>
      </template>
      <template
        v-if="canWriteUsers && group"
        #actions
      >
        <ConfirmButton
          label="Delete"
          title="Delete group?"
          :message="`${group.display_name} and its memberships and role assignments are deleted.`"
          danger
          :action="remove"
        />
      </template>
    </PageHeader>
    <ErrorAlert :error="loader.error.value" />
    <div
      v-if="group"
      class="grid gap-4 xl:grid-cols-2"
    >
      <form
        class="card space-y-4"
        @submit.prevent="save"
      >
        <h2 class="font-semibold">
          Properties
        </h2>
        <div>
          <label
            class="label"
            for="gd-name"
          >Name</label>
          <input
            id="gd-name"
            v-model="name"
            class="input"
            :disabled="!canWriteUsers"
            required
          >
        </div>
        <div>
          <label
            class="label"
            for="gd-desc"
          >Description</label>
          <input
            id="gd-desc"
            v-model="description"
            class="input"
            :disabled="!canWriteUsers"
          >
        </div>
        <p class="mono muted">
          Object ID {{ group.id }}
        </p>
        <button
          v-if="canWriteUsers"
          type="submit"
          class="btn btn-primary"
          :disabled="saver.busy.value"
        >
          Save
        </button>
      </form>
      <div class="space-y-3">
        <h2 class="font-semibold">
          Members
        </h2>
        <PrincipalPicker
          v-if="canWriteUsers"
          kind="user"
          label="Add member"
          @select="addMember"
        />
        <ErrorAlert :error="saver.error.value" />
        <ListShell
          :list="members"
          empty="No members yet."
        >
          <table class="table">
            <thead>
              <tr>
                <th scope="col">
                  Member
                </th>
                <th scope="col">
                  <span class="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="m in members.items"
                :key="m.id"
              >
                <td>
                  <RouterLink
                    :to="{ name: 'admin-user', params: { tenant, id: m.id } }"
                    class="btn-link"
                  >
                    {{ m.display_name || m.email }}
                  </RouterLink>
                  <span class="muted block text-xs">{{ m.email }}</span>
                </td>
                <td class="text-right">
                  <ConfirmButton
                    v-if="canWriteUsers"
                    label="Remove"
                    title="Remove member?"
                    :message="`Remove ${m.email} from this group?`"
                    danger
                    :action="() => removeMember(m.id)"
                    @done="members.reload()"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </ListShell>
      </div>
    </div>
  </section>
</template>
