<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { me as meApi } from '@/api/me'
import type { Session } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { useAuthStore } from '@/stores/auth'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import SessionsTable from '@/components/SessionsTable.vue'

const sessions = ref<Session[]>([])
const { error, run } = useAction()
const auth = useAuthStore()

async function load() {
  const res = await run(meApi.sessions)
  if (res) sessions.value = res.items
}

onMounted(load)

async function revokeAll() {
  await meApi.revokeAllSessions()
  // This browser's session is gone too: its token no longer works, so sign in again.
  await auth.reauthenticate(true)
}

function revoke(sessionId: string) {
  return meApi.revokeSession(sessionId)
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <p class="muted text-sm">
        Browsers and devices where you're signed in.
      </p>
      <ConfirmButton
        v-if="sessions.length"
        label="Sign out everywhere"
        title="Sign out everywhere?"
        message="Every session ends, including this one, and apps lose their refresh tokens. You'll need to sign in again."
        danger
        :action="revokeAll"
      />
    </div>
    <ErrorAlert :error="error" />
    <div class="card p-0 sm:p-0">
      <SessionsTable
        v-if="sessions.length"
        :sessions="sessions"
      >
        <template #action="{ session }">
          <ConfirmButton
            v-if="!session.current"
            label="Sign out"
            title="Sign out this session?"
            message="That device is signed out and the apps signed in there lose their refresh tokens."
            danger
            :action="() => revoke(session.id)"
            @done="load"
          />
        </template>
      </SessionsTable>
      <p
        v-else-if="!error"
        class="muted p-4 text-sm"
      >
        No active sessions.
      </p>
    </div>
  </div>
</template>
