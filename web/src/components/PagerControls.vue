<script setup lang="ts">
defineProps<{ hasPrev: boolean; hasNext: boolean; busy?: boolean; page: number }>()
const emit = defineEmits<{ prev: []; next: [] }>()
</script>

<template>
  <div
    v-if="hasPrev || hasNext"
    class="mt-3 flex items-center justify-end gap-2 text-sm"
  >
    <span class="muted">Page {{ page }}</span>
    <button
      type="button"
      class="btn"
      :disabled="!hasPrev || busy"
      @click="emit('prev')"
    >
      Previous
    </button>
    <button
      type="button"
      class="btn"
      :disabled="!hasNext || busy"
      @click="emit('next')"
    >
      Next
    </button>
  </div>
</template>
