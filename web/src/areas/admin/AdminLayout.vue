<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'
import { adminNav } from './nav'

const { slug } = storeToRefs(useTenantStore())
</script>

<template>
  <div class="flex min-h-screen flex-col">
    <header
      class="flex h-12 items-center gap-3 border-b border-neutral-200 bg-white px-4 dark:border-neutral-800 dark:bg-neutral-900"
    >
      <span class="font-semibold">Admin center</span>
      <span class="text-sm text-neutral-500 dark:text-neutral-400">{{ slug }}</span>
    </header>
    <div class="flex flex-1">
      <nav
        aria-label="Admin sections"
        class="w-56 shrink-0 border-r border-neutral-200 bg-white p-2 dark:border-neutral-800 dark:bg-neutral-900"
      >
        <ul class="space-y-1">
          <li>
            <RouterLink
              :to="{ name: 'admin', params: { tenant: slug } }"
              class="nav-link"
              exact-active-class="nav-link-active"
            >
              Overview
            </RouterLink>
          </li>
          <li
            v-for="item in adminNav"
            :key="item.name"
          >
            <RouterLink
              :to="{ name: item.name, params: { tenant: slug } }"
              class="nav-link"
              active-class="nav-link-active"
            >
              {{ item.label }}
            </RouterLink>
          </li>
        </ul>
      </nav>
      <main class="flex-1 p-6">
        <RouterView />
      </main>
    </div>
  </div>
</template>

<style scoped>
@reference 'tailwindcss';

.nav-link {
  @apply block rounded px-3 py-2 text-sm text-neutral-700 hover:bg-neutral-100 focus-visible:outline-2 focus-visible:outline-blue-600 dark:text-neutral-300 dark:hover:bg-neutral-800;
}
.nav-link-active {
  @apply bg-neutral-100 font-medium text-neutral-900 dark:bg-neutral-800 dark:text-neutral-100;
}
</style>
