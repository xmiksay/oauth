<script setup lang="ts">
import { onMounted, ref } from 'vue'
import type { TxView } from '@/api/authn'

defineProps<{ view: TxView; locked: boolean }>()
const emit = defineEmits<{ decide: [approve: boolean] }>()

const root = ref<HTMLElement | null>(null)
// Focus the request itself so it is read before the buttons.
onMounted(() => root.value?.focus())
</script>

<template>
  <div class="space-y-4">
    <p
      ref="root"
      tabindex="-1"
      class="text-sm focus:outline-none"
    >
      <strong>{{ view.client.display_name }}</strong> wants to access
      <strong>{{ view.consent?.resource.display_name }}</strong> on your behalf.
    </p>
    <div>
      <h2 class="text-sm font-medium">
        This app will be able to:
      </h2>
      <ul
        class="mt-2 divide-y divide-neutral-200 rounded-md border border-neutral-200 dark:divide-neutral-800 dark:border-neutral-800"
      >
        <li
          v-for="scope in view.consent?.scopes ?? []"
          :key="scope.value"
          class="px-3 py-2 text-sm"
        >
          <span class="block">{{ scope.description || scope.value }}</span>
          <span class="mono muted">{{ scope.value }}</span>
        </li>
      </ul>
    </div>
    <p class="muted text-xs">
      Accepting allows this app to use your data as described. You can withdraw this permission
      later in My Account.
    </p>
    <div class="flex gap-2">
      <button
        type="button"
        class="btn flex-1"
        :disabled="locked"
        @click="emit('decide', false)"
      >
        Cancel
      </button>
      <button
        type="button"
        class="btn btn-primary flex-1"
        :disabled="locked"
        @click="emit('decide', true)"
      >
        Accept
      </button>
    </div>
  </div>
</template>
