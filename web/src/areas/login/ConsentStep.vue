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
    <template v-if="view.device">
      <p
        ref="root"
        tabindex="-1"
        class="text-sm focus:outline-none"
      >
        Sign in to <strong>{{ view.client.display_name }}</strong> on another device as
        <strong>{{ view.user?.email }}</strong>?
      </p>
      <p
        class="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
      >
        Only continue if you started this sign-in yourself on a device in front of you. Never
        enter a code that someone sent or told you.
      </p>
    </template>
    <p
      v-else
      ref="root"
      tabindex="-1"
      class="text-sm focus:outline-none"
    >
      <strong>{{ view.client.display_name }}</strong> wants to access
      <strong>{{ view.consent?.resource.display_name }}</strong> on your behalf.
    </p>
    <div v-if="view.consent">
      <h2 class="text-sm font-medium">
        <template v-if="view.device">
          The device will be able to access {{ view.consent.resource.display_name }} to:
        </template>
        <template v-else>
          This app will be able to:
        </template>
      </h2>
      <ul
        class="mt-2 divide-y divide-neutral-200 rounded-md border border-neutral-200 dark:divide-neutral-800 dark:border-neutral-800"
      >
        <li
          v-for="scope in view.consent.scopes"
          :key="scope.value"
          class="px-3 py-2 text-sm"
        >
          <span class="block">{{ scope.description || scope.value }}</span>
          <span class="mono muted">{{ scope.value }}</span>
        </li>
      </ul>
    </div>
    <p class="muted text-xs">
      <template v-if="view.device">
        You can sign the device out later in My Account under Devices &amp; sessions.
      </template>
      <template v-else>
        Accepting allows this app to use your data as described. You can withdraw this permission
        later in My Account.
      </template>
    </p>
    <div class="flex gap-2">
      <button
        type="button"
        class="btn flex-1"
        :disabled="locked"
        @click="emit('decide', false)"
      >
        {{ view.device ? 'Deny' : 'Cancel' }}
      </button>
      <button
        type="button"
        class="btn btn-primary flex-1"
        :disabled="locked"
        @click="emit('decide', true)"
      >
        {{ view.device ? 'Allow' : 'Accept' }}
      </button>
    </div>
  </div>
</template>
