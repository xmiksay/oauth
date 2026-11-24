<script setup lang="ts">
/**
 * Detail-page notice on an object `oauth apply` manages; the slot says what the next apply
 * puts back for that kind of object.
 */
</script>

<template>
  <p
    role="note"
    class="mb-4 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200"
    data-testid="managed-note"
  >
    Managed by <code>oauth apply</code>: <slot />
  </p>
</template>
