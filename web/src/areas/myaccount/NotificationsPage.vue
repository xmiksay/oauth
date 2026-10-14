<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { me as meApi } from '@/api/me'
import type { NotificationEvent, NotificationSettings } from '@/api/types'
import { useAction } from '@/composables/useAction'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'

const EVENT_LABELS: Record<NotificationEvent, string> = {
  password_changed: 'Your password was changed',
  mfa_changed: 'Two-step verification was changed',
  email_changed: 'Your sign-in email was changed',
  new_sign_in: 'New sign-in to your account',
  token_reuse: 'Possible stolen sign-in detected (an app was signed out for safety)',
}

const { me } = storeToRefs(useAuthStore())
const settings = ref<NotificationSettings | null>(null)
const loader = useAction()
const saver = useAction()
const saved = ref(false)

onMounted(async () => {
  const s = await loader.run(meApi.notifications)
  if (s) settings.value = s
})

async function save() {
  if (!settings.value) return
  saved.value = false
  const s = await saver.run(() => meApi.updateNotifications(settings.value?.items ?? []))
  if (s) {
    settings.value = s
    saved.value = true
  }
}
</script>

<template>
  <div class="space-y-4">
    <ErrorAlert :error="loader.error.value" />
    <form
      v-if="settings"
      class="card space-y-4"
      @submit.prevent="save"
      @change="saved = false"
    >
      <h2 class="text-lg font-semibold">
        Security notifications
      </h2>
      <p class="muted text-sm">
        Choose which security events we tell you about.
      </p>
      <p
        v-if="!settings.channels.email"
        class="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
      >
        Email notifications are unavailable: this server is not set up to send email.
      </p>
      <p
        v-else-if="me && !me.email_verified"
        class="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
      >
        Notifications are sent only to a verified address, and yours isn't verified yet.
        <RouterLink
          :to="{ name: 'myaccount' }"
          class="btn-link"
        >
          Verify it on your profile
        </RouterLink>
      </p>
      <div class="overflow-x-auto">
        <table class="table">
          <thead>
            <tr>
              <th scope="col">
                Event
              </th>
              <th
                scope="col"
                class="w-20 text-center"
              >
                Email
              </th>
              <th
                v-if="settings.channels.telegram"
                scope="col"
                class="w-20 text-center"
              >
                Telegram
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="item in settings.items"
              :key="item.event"
            >
              <td>{{ EVENT_LABELS[item.event] ?? item.event }}</td>
              <td class="text-center">
                <input
                  v-model="item.email"
                  type="checkbox"
                  :aria-label="`Email: ${EVENT_LABELS[item.event] ?? item.event}`"
                  :disabled="!settings.channels.email"
                  :data-testid="`email-${item.event}`"
                >
              </td>
              <td
                v-if="settings.channels.telegram"
                class="text-center"
              >
                <input
                  v-model="item.telegram"
                  type="checkbox"
                  :aria-label="`Telegram: ${EVENT_LABELS[item.event] ?? item.event}`"
                  :data-testid="`telegram-${item.event}`"
                >
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <ErrorAlert :error="saver.error.value" />
      <StatusNote :message="saved ? 'Saved.' : null" />
      <button
        type="submit"
        class="btn btn-primary"
        :disabled="saver.busy.value || !(settings.channels.email || settings.channels.telegram)"
      >
        Save
      </button>
    </form>
    <p
      v-else-if="loader.busy.value"
      class="muted"
      aria-live="polite"
    >
      Loading…
    </p>
  </div>
</template>
