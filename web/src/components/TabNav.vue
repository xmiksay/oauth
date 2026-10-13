<script setup lang="ts">
import type { RouteLocationRaw } from 'vue-router'

defineProps<{ label: string; items: { to: RouteLocationRaw; label: string; exact?: boolean }[] }>()
</script>

<template>
  <nav
    :aria-label="label"
    class="-mx-1 flex gap-1 overflow-x-auto border-b border-neutral-200 dark:border-neutral-800"
  >
    <RouterLink
      v-for="item in items"
      :key="item.label"
      :to="item.to"
      class="shrink-0 border-b-2 border-transparent px-3 py-2 text-sm whitespace-nowrap text-neutral-600 hover:text-neutral-900 focus-visible:outline-2 focus-visible:outline-blue-600 dark:text-neutral-400 dark:hover:text-neutral-100"
      :active-class="item.exact ? '' : 'tab-active'"
      :exact-active-class="item.exact ? 'tab-active' : ''"
    >
      {{ item.label }}
    </RouterLink>
  </nav>
</template>

<style scoped>
@reference 'tailwindcss';

.tab-active {
  @apply border-blue-700 font-medium text-neutral-900 dark:border-blue-400 dark:text-neutral-100;
}
</style>
