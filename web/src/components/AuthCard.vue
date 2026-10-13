<script setup lang="ts">
import { useId } from 'vue'

/** The centred card of the sign-in and sign-out pages. */
defineProps<{ title: string; tenant?: string | null; subtitle?: string | null }>()
const titleId = useId()
</script>

<template>
  <main class="flex min-h-screen items-start justify-center px-4 py-10 sm:items-center">
    <section
      :aria-labelledby="titleId"
      class="card w-full max-w-md sm:p-8"
    >
      <p
        v-if="tenant"
        class="text-sm font-medium text-neutral-500 dark:text-neutral-400"
      >
        {{ tenant }}
      </p>
      <h1
        :id="titleId"
        class="mt-1 text-2xl font-semibold"
      >
        {{ title }}
      </h1>
      <p
        v-if="subtitle"
        class="muted mt-1 text-sm"
      >
        {{ subtitle }}
      </p>
      <div class="mt-6">
        <slot />
      </div>
    </section>
  </main>
</template>
