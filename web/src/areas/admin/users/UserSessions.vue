<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { users } from '@/api/directory'
import type { Session } from '@/api/types'
import { useAction } from '@/composables/useAction'
import ErrorAlert from '@/components/ErrorAlert.vue'
import SessionsTable from '@/components/SessionsTable.vue'

const props = defineProps<{ userId: string }>()
const sessions = ref<Session[]>([])
const { error, run } = useAction()

onMounted(async () => {
  const res = await run(() => users.sessions(props.userId))
  if (res) sessions.value = res.items
})
</script>

<template>
  <div class="card">
    <h2 class="font-semibold">
      Active sessions
    </h2>
    <ErrorAlert :error="error" />
    <SessionsTable
      v-if="sessions.length"
      class="mt-3"
      :sessions="sessions"
    />
    <p
      v-else-if="!error"
      class="muted mt-3 text-sm"
    >
      No active sessions.
    </p>
  </div>
</template>
