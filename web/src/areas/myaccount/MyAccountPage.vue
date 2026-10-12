<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'

const { slug } = storeToRefs(useTenantStore())
</script>

<template>
  <main class="mx-auto max-w-3xl p-6">
    <p class="text-sm text-neutral-500 dark:text-neutral-400">
      {{ slug }}
    </p>
    <h1 class="mt-1 text-2xl font-semibold">
      My account
    </h1>
    <p class="mt-4 text-neutral-600 dark:text-neutral-400">
      Profile, password, MFA, sessions and app consents will live here.
    </p>
  </main>
</template>
