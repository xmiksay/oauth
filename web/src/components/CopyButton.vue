<script setup lang="ts">
import { ref } from 'vue'

const props = defineProps<{ text: string; label?: string }>()
const copied = ref(false)
const failed = ref(false)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.text)
    copied.value = true
    failed.value = false
    setTimeout(() => (copied.value = false), 2000)
  } catch {
    failed.value = true
  }
}
</script>

<template>
  <button
    type="button"
    class="btn"
    @click="copy"
  >
    {{ copied ? 'Copied' : failed ? 'Copy failed — select and copy manually' : (label ?? 'Copy') }}
  </button>
</template>
