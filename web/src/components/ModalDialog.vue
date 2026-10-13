<script setup lang="ts">
import { nextTick, onMounted, ref, useId, watch } from 'vue'

const props = defineProps<{ open: boolean; title: string; wide?: boolean }>()
const emit = defineEmits<{ close: [] }>()

const el = ref<HTMLDialogElement | null>(null)
const titleId = useId()

async function sync() {
  await nextTick()
  const d = el.value
  if (!d) return
  if (props.open && !d.open) {
    // Native modal: focus trap, inert background and Esc for free (jsdom lacks showModal).
    if (typeof d.showModal === 'function') d.showModal()
    else d.setAttribute('open', '')
  } else if (!props.open && d.open) {
    if (typeof d.close === 'function') d.close()
    else d.removeAttribute('open')
  }
}

watch(() => props.open, sync)
onMounted(sync)
</script>

<template>
  <dialog
    ref="el"
    :aria-labelledby="titleId"
    class="m-auto w-[calc(100%-2rem)] rounded-lg border border-neutral-200 bg-white p-0 text-neutral-900 shadow-xl backdrop:bg-black/40 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-100"
    :class="wide ? 'max-w-2xl' : 'max-w-lg'"
    @cancel.prevent="emit('close')"
  >
    <div
      v-if="open"
      class="p-5 sm:p-6"
    >
      <h2
        :id="titleId"
        class="text-lg font-semibold"
      >
        {{ title }}
      </h2>
      <div class="mt-4">
        <slot />
      </div>
      <div
        v-if="$slots.actions"
        class="mt-6 flex flex-wrap justify-end gap-2"
      >
        <slot name="actions" />
      </div>
    </div>
  </dialog>
</template>
