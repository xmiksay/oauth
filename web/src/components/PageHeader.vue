<script setup lang="ts">
defineProps<{ title: string; description?: string }>()
</script>

<template>
  <div class="mb-5 flex flex-wrap items-start justify-between gap-3">
    <div class="min-w-0">
      <slot name="breadcrumb" />
      <h1 class="truncate text-2xl font-semibold">
        {{ title }}
      </h1>
      <p
        v-if="description"
        class="muted mt-1 text-sm"
      >
        {{ description }}
      </p>
    </div>
    <div
      v-if="$slots.actions"
      class="flex flex-wrap gap-2"
    >
      <slot name="actions" />
    </div>
  </div>
</template>
