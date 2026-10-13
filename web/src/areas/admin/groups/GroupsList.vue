<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'
import { useAuthStore } from '@/stores/auth'
import { groups } from '@/api/directory'
import type { Group } from '@/api/types'
import { usePagedList } from '@/composables/usePagedList'
import { useAction } from '@/composables/useAction'
import PageHeader from '@/components/PageHeader.vue'
import ListShell from '@/components/ListShell.vue'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'

const router = useRouter()
const { slug } = storeToRefs(useTenantStore())
const { canWriteUsers } = storeToRefs(useAuthStore())
const list = usePagedList<Group>(groups.list)

const creating = ref(false)
const name = ref('')
const description = ref('')
const { busy, error, run } = useAction()

function openCreate() {
  name.value = ''
  description.value = ''
  error.value = null
  creating.value = true
}

async function create() {
  const g = await run(() =>
    groups.create({
      display_name: name.value.trim(),
      ...(description.value.trim() ? { description: description.value.trim() } : {}),
    }),
  )
  if (g) await router.push({ name: 'admin-group', params: { tenant: slug.value, id: g.id } })
}
</script>

<template>
  <section>
    <PageHeader
      title="Groups"
      description="Groups can be assigned app roles as a whole."
    >
      <template
        v-if="canWriteUsers"
        #actions
      >
        <button
          type="button"
          class="btn btn-primary"
          @click="openCreate"
        >
          New group
        </button>
      </template>
    </PageHeader>
    <ListShell
      :list="list"
      search-label="Search groups"
      empty="No groups found."
    >
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              Name
            </th>
            <th scope="col">
              Description
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="g in list.items"
            :key="g.id"
          >
            <td>
              <RouterLink
                :to="{ name: 'admin-group', params: { tenant: slug, id: g.id } }"
                class="btn-link"
              >
                {{ g.display_name }}
              </RouterLink>
            </td>
            <td class="muted">
              {{ g.description }}
            </td>
          </tr>
        </tbody>
      </table>
    </ListShell>
    <ModalDialog
      :open="creating"
      title="New group"
      @close="creating = false"
    >
      <form
        id="create-group"
        class="space-y-4"
        @submit.prevent="create"
      >
        <div>
          <label
            class="label"
            for="cg-name"
          >Name</label>
          <input
            id="cg-name"
            v-model="name"
            class="input"
            required
          >
        </div>
        <div>
          <label
            class="label"
            for="cg-desc"
          >Description</label>
          <input
            id="cg-desc"
            v-model="description"
            class="input"
          >
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
          form="create-group"
          class="btn btn-primary"
          :disabled="busy"
        >
          Create
        </button>
      </template>
    </ModalDialog>
  </section>
</template>
