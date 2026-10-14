<script setup lang="ts">
import { computed, watch } from 'vue'
import { useRoute } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useApplicationStore } from '@/stores/application'
import PageHeader from '@/components/PageHeader.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import TabNav from '@/components/TabNav.vue'

const route = useRoute()
const store = useApplicationStore()
const { app, error, loading } = storeToRefs(store)

watch(
  () => route.params.id,
  (id) => {
    if (typeof id === 'string') store.load(id)
  },
  { immediate: true },
)

const tabs = computed(() => {
  const params = { id: route.params.id }
  return [
    { to: { name: 'admin-app', params }, label: 'Overview', exact: true },
    { to: { name: 'admin-app-auth', params }, label: 'Authentication' },
    { to: { name: 'admin-app-secrets', params }, label: 'Certificates & secrets' },
    { to: { name: 'admin-app-token', params }, label: 'Token configuration' },
    { to: { name: 'admin-app-expose', params }, label: 'Expose an API' },
    { to: { name: 'admin-app-roles', params }, label: 'App roles' },
    { to: { name: 'admin-app-permissions', params }, label: 'API permissions' },
  ]
})
</script>

<template>
  <section>
    <PageHeader
      :title="app?.display_name ?? 'Application'"
      :description="app ? `Client ID ${app.client_id}` : undefined"
    >
      <template #breadcrumb>
        <RouterLink
          :to="{ name: 'admin-apps' }"
          class="btn-link"
        >
          App registrations
        </RouterLink>
      </template>
    </PageHeader>
    <ErrorAlert :error="error" />
    <p
      v-if="loading && !app"
      class="muted"
    >
      Loading…
    </p>
    <template v-if="app">
      <p
        v-if="app.builtin"
        class="mb-4 rounded-md border border-blue-200 bg-blue-50 px-3 py-2 text-sm text-blue-900 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-200"
      >
        Built-in application: only a Global Administrator can change its name and token lifetimes.
      </p>
      <TabNav
        label="Application sections"
        :items="tabs"
      />
      <div class="pt-5">
        <RouterView />
      </div>
    </template>
  </section>
</template>
