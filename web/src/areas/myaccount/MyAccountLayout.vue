<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'
import AppHeader from '@/components/AppHeader.vue'
import SignedInGate from '@/components/SignedInGate.vue'
import TabNav from '@/components/TabNav.vue'

const { slug } = storeToRefs(useTenantStore())
const route = useRoute()

const tabs = computed(() => {
  const params = { tenant: slug.value }
  return [
    { to: { name: 'myaccount', params }, label: 'Profile', exact: true },
    { to: { name: 'myaccount-security', params }, label: 'Security info' },
    { to: { name: 'myaccount-sessions', params }, label: 'Devices & sessions' },
    { to: { name: 'myaccount-apps', params }, label: 'App permissions' },
  ]
})
</script>

<template>
  <div class="flex min-h-screen flex-col">
    <AppHeader
      title="My Account"
      :tenant="slug"
    />
    <SignedInGate>
      <main class="mx-auto w-full max-w-4xl p-4 sm:p-6">
        <h1 class="mb-4 text-2xl font-semibold">
          {{ route.meta.title }}
        </h1>
        <TabNav
          label="My Account sections"
          :items="tabs"
        />
        <div class="pt-6">
          <RouterView />
        </div>
      </main>
    </SignedInGate>
  </div>
</template>
