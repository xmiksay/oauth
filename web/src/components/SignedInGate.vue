<script setup lang="ts">
import { onMounted } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { me as meApi } from '@/api/me'
import { useAction } from '@/composables/useAction'
import ErrorAlert from './ErrorAlert.vue'

/** Loads the signed-in user (`GET me`) before rendering an area; shows load / auth failures. */
const auth = useAuthStore()
const { me, fatal } = storeToRefs(auth)
const { error, run } = useAction()

onMounted(async () => {
  const detail = await run(meApi.get)
  if (detail) auth.setMe(detail)
})
</script>

<template>
  <div
    v-if="fatal"
    class="p-6"
  >
    <ErrorAlert :error="fatal" />
  </div>
  <div
    v-else-if="error"
    class="p-6"
  >
    <ErrorAlert :error="error" />
  </div>
  <slot v-else-if="me" />
  <p
    v-else
    class="muted p-6"
    aria-live="polite"
  >
    Loading…
  </p>
</template>
