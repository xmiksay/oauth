<script setup lang="ts">
/**
 * Success note ("Saved."). The live region is always in the DOM — screen readers only
 * announce changes to a region that already exists.
 */
defineProps<{ message: string | null }>()
</script>

<template>
  <p
    role="status"
    aria-live="polite"
    class="text-sm text-green-700 dark:text-green-400"
  >
    {{ message ?? '' }}
  </p>
</template>
