<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'

const { slug } = storeToRefs(useTenantStore())
</script>

<template>
  <section>
    <h1 class="text-2xl font-semibold">
      Overview
    </h1>
    <p class="mt-2 text-neutral-600 dark:text-neutral-400">
      Directory <strong>{{ slug }}</strong> — pick a section from the navigation.
    </p>
  </section>
</template>
