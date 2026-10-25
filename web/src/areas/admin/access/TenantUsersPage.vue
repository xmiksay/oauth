<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { useTenantStore } from '@/stores/tenant'
import PageHeader from '@/components/PageHeader.vue'
import { SYSTEM_TENANT } from '../nav'
import TenantUsersList from './TenantUsersList.vue'

const route = useRoute()
// The component is reused across /admin/tenants/:slug/users, so follow the param — but only
// while it is a string: leaving the route drops it, which must not remount the list for "undefined".
const slugParam = () => (typeof route.params.slug === 'string' ? route.params.slug : '')
const target = ref(slugParam())
watch(slugParam, (s) => {
  if (s) target.value = s
})
const { slug } = storeToRefs(useTenantStore())
const { isGlobalAdmin } = storeToRefs(useAuthStore())
const allowed = computed(() => slug.value === SYSTEM_TENANT && isGlobalAdmin.value)
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
    <!-- Keyed on the slug: another tenant remounts with fresh search, cursors and selection. -->
    <TenantUsersList
      v-else-if="target"
      :key="target"
      :slug="target"
    />
  </section>
</template>
