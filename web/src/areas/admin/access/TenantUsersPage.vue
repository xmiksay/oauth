<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { storeToRefs } from 'pinia'
import { tenants } from '@/api/access'
import type { PageQuery, User } from '@/api/types'
import { useAuthStore } from '@/stores/auth'
import { useTenantStore } from '@/stores/tenant'
import { usePagedList } from '@/composables/usePagedList'
import PageHeader from '@/components/PageHeader.vue'
import ListShell from '@/components/ListShell.vue'
import { SYSTEM_TENANT } from '../nav'
import TenantUserPanel from './TenantUserPanel.vue'

const route = useRoute()
// The component is reused across /admin/tenants/:slug/users, so follow the param.
const target = computed(() => String(route.params.slug))
const { slug } = storeToRefs(useTenantStore())
const { isGlobalAdmin } = storeToRefs(useAuthStore())
const allowed = computed(() => slug.value === SYSTEM_TENANT && isGlobalAdmin.value)

const list = usePagedList<User>((q: PageQuery) => tenants.users(target.value, q))
const selected = ref<string | null>(null)

watch(
  () => route.params.slug,
  (next) => {
    // Leaving the route also changes the param (to undefined) before unmount.
    if (typeof next !== 'string') return
    selected.value = null
    // The old tenant's search doesn't apply; the debounced search reload sees the reset
    // as already requested, so this reload is the only request.
    list.setSearch('')
    if (allowed.value) void list.reload()
  },
)
</script>

<template>
  <section>
    <PageHeader
      :title="`Users of ${target}`"
      description="Rescue a locked-out user: reset their password or second factors."
    >
      <template #breadcrumb>
        <RouterLink
          :to="{ name: 'admin-tenants' }"
          class="btn-link"
        >
          Tenants
        </RouterLink>
      </template>
    </PageHeader>
    <p
      v-if="!allowed"
      class="muted text-sm"
    >
      Only a Global Administrator of the system tenant can manage other tenants' users.
    </p>
    <div
      v-else
      class="grid gap-4 xl:grid-cols-2"
    >
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
              :aria-selected="selected === u.id"
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
        :slug="target"
        :user-id="selected"
        @changed="list.load()"
      />
    </div>
  </section>
</template>
