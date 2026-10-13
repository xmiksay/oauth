<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { me as meApi } from '@/api/me'
import type { MyConsent } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'

const consents = ref<MyConsent[]>([])
const { error, busy, run } = useAction()

async function load() {
  const res = await run(meApi.consents)
  if (res) consents.value = res.items
}

onMounted(load)

function revoke(consentId: string) {
  return meApi.revokeConsent(consentId)
}
</script>

<template>
  <div class="space-y-4">
    <p class="muted text-sm">
      Apps you have allowed to access data on your behalf. Permissions granted by your
      administrator for everyone are not listed.
    </p>
    <ErrorAlert :error="error" />
    <ul
      v-if="consents.length"
      class="space-y-3"
    >
      <li
        v-for="c in consents"
        :key="c.id"
        class="card flex flex-wrap items-start justify-between gap-3"
      >
        <div class="min-w-0">
          <h2 class="font-semibold">
            {{ c.client.display_name }}
          </h2>
          <p class="muted text-sm">
            can access <strong>{{ c.resource.display_name }}</strong>:
          </p>
          <p class="mt-1 flex flex-wrap gap-1">
            <span
              v-for="s in c.scopes"
              :key="s"
              class="badge mono"
            >{{ s }}</span>
          </p>
          <p class="muted mt-1 text-xs">
            Granted {{ formatDate(c.created_at) }}
          </p>
        </div>
        <ConfirmButton
          label="Revoke"
          title="Revoke access?"
          :message="`${c.client.display_name} loses access to ${c.resource.display_name} and its refresh tokens are revoked. It will ask for permission again next time.`"
          danger
          :action="() => revoke(c.id)"
          @done="load"
        />
      </li>
    </ul>
    <p
      v-else-if="!busy && !error"
      class="card muted text-sm"
    >
      You haven't granted any app permissions.
    </p>
  </div>
</template>
