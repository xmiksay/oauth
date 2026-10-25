<script setup lang="ts">
import { ref } from 'vue'
import { tenants } from '@/api/access'
import type { PageQuery, User } from '@/api/types'
import { usePagedList } from '@/composables/usePagedList'
import ListShell from '@/components/ListShell.vue'
import TenantUserPanel from './TenantUserPanel.vue'

// One tenant's users; the page keys this on the slug, so another tenant gets fresh state.
const props = defineProps<{ slug: string }>()

const list = usePagedList<User>((q: PageQuery) => tenants.users(props.slug, q))
const selected = ref<string | null>(null)
</script>

<template>
  <div class="grid gap-4 xl:grid-cols-2">
    <ListShell
      :list="list"
      search-label="Search by name or email"
      empty="No users found."
    >
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              Email
            </th>
            <th scope="col">
              Display name
            </th>
            <th scope="col">
              Status
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="u in list.items"
            :key="u.id"
            :aria-current="selected === u.id ? 'true' : undefined"
            :class="{ 'bg-black/5 dark:bg-white/10': selected === u.id }"
          >
            <td class="break-all">
              <button
                type="button"
                class="btn-link text-left"
                @click="selected = u.id"
              >
                {{ u.email }}
              </button>
            </td>
            <td>{{ u.display_name || '(no name)' }}</td>
            <td class="space-x-1">
              <span
                v-if="u.disabled"
                class="badge"
              >Disabled</span>
              <span
                v-if="!u.has_password"
                class="badge"
              >No password</span>
            </td>
          </tr>
        </tbody>
      </table>
    </ListShell>
    <TenantUserPanel
      v-if="selected"
      :key="selected"
      :slug="slug"
      :user-id="selected"
      @changed="list.load()"
    />
  </div>
</template>
