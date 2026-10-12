<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'

const { slug } = storeToRefs(useTenantStore())
</script>

<template>
  <main class="flex min-h-screen items-center justify-center p-4">
    <section
      aria-labelledby="login-title"
      class="w-full max-w-sm rounded-lg border border-neutral-200 bg-white p-8 shadow-sm dark:border-neutral-800 dark:bg-neutral-900"
    >
      <p class="text-sm text-neutral-500 dark:text-neutral-400">
        {{ slug }}
      </p>
      <h1
        id="login-title"
        class="mt-1 text-2xl font-semibold"
      >
        Sign in
      </h1>
      <p class="mt-4 text-neutral-600 dark:text-neutral-400">
        Sign-in is not available yet.
      </p>
    </section>
  </main>
</template>
