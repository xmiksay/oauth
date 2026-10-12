<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()
const title = computed(() => (typeof route.meta.title === 'string' ? route.meta.title : ''))
</script>

<template>
  <section>
    <h1 class="text-2xl font-semibold">
      {{ title }}
    </h1>
    <p class="mt-2 text-neutral-600 dark:text-neutral-400">
      Coming soon.
    </p>
  </section>
</template>
