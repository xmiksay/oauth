<script setup lang="ts">
/** Marks an object `oauth apply` created or adopted from a tenant file. */
defineProps<{ managed: boolean }>()
</script>

<template>
  <span
    v-if="managed"
    class="badge ml-1"
    title="Declared in a tenant file: the next `oauth apply` overwrites changes made here"
  >Managed by apply</span>
</template>
