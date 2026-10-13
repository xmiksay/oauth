<script setup lang="ts">
import { computed } from 'vue'
import { encode } from 'uqr'

const props = defineProps<{ value: string; label: string }>()

const qr = computed(() => encode(props.value, { ecc: 'M', border: 2 }))
// One path of 1×1 squares keeps the SVG small and crisp at any size.
const path = computed(() => {
  let d = ''
  qr.value.data.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark) d += `M${x} ${y}h1v1h-1z`
    }),
  )
  return d
})
</script>

<template>
  <svg
    role="img"
    :aria-label="label"
    :viewBox="`0 0 ${qr.size} ${qr.size}`"
    class="h-48 w-48 rounded bg-white"
    shape-rendering="crispEdges"
  >
    <rect
      :width="qr.size"
      :height="qr.size"
      fill="#fff"
    />
    <path
      :d="path"
      fill="#000"
    />
  </svg>
</template>
