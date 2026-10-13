<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const router = useRouter()
const failed = ref(false)
const tenant = String(route.params.tenant ?? '')
const area = route.meta.area ?? 'myaccount'

onMounted(async () => {
  try {
    const next = await useAuthStore().completeSignIn(tenant, area)
    await router.replace(next)
  } catch {
    // An `error` from the authorize endpoint (e.g. access_denied) or a stale/replayed callback.
    failed.value = true
  }
})
</script>

<template>
  <main
    class="flex min-h-screen flex-col items-center justify-center gap-3 p-4 text-center"
    aria-live="polite"
  >
    <template v-if="failed">
      <p class="font-medium">
        Sign-in could not be completed.
      </p>
      <RouterLink
        class="btn btn-primary"
        :to="`/${tenant}/${area}`"
      >
        Try again
      </RouterLink>
    </template>
    <p
      v-else
      class="muted"
    >
      Completing sign-in…
    </p>
  </main>
</template>
