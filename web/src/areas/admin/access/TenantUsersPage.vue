<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { useTenantStore } from '@/stores/tenant'
import PageHeader from '@/components/PageHeader.vue'
import { SYSTEM_TENANT } from '../nav'
import TenantUsersList from './TenantUsersList.vue'

// Read once: `AdminLayout` keys the page on the slug (`adminPageKey`), so another tenant is a
// fresh mount with fresh search, cursors and selection, and leaving the route (which drops the
// param) never turns into a fetch for "undefined".
const target = String(useRoute().params.slug)
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
    <TenantUsersList
      v-else
      :slug="target"
    />
  </section>
</template>
