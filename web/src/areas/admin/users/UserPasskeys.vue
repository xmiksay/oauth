<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ApiError } from '@/api/client'
import { users } from '@/api/directory'
import type { Passkey } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'

/** A user's passkeys; `canWrite` adds a remove button per passkey. */
const props = defineProps<{ userId: string; canWrite: boolean }>()
const emit = defineEmits<{ changed: [] }>()

const passkeys = ref<Passkey[]>([])
const { error, run } = useAction()

async function load() {
  const res = await run(() => users.passkeys(props.userId))
  if (res) passkeys.value = res.items
}
onMounted(load)

async function remove(p: Passkey) {
  try {
    await users.removePasskey(props.userId, p.id)
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      throw "This is the user's only way to sign in. Set a password first (reset password), then remove the passkey."
    }
    throw err
  }
  await load()
  emit('changed')
}
</script>

<template>
  <div class="card">
    <h2 class="font-semibold">
      Passkeys
    </h2>
    <ErrorAlert :error="error" />
    <div
      v-if="passkeys.length"
      class="mt-3 overflow-x-auto"
    >
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              Name
            </th>
            <th
              scope="col"
              class="hidden sm:table-cell"
            >
              Added
            </th>
            <th scope="col">
              Last used
            </th>
            <th
              v-if="canWrite"
              scope="col"
            >
              <span class="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="p in passkeys"
            :key="p.id"
          >
            <td>
              {{ p.name }}
              <span class="badge ml-1">{{ p.backup_state ? 'Synced' : 'Device-bound' }}</span>
            </td>
            <td class="hidden sm:table-cell">
              {{ formatDate(p.created_at) }}
            </td>
            <td>{{ p.last_used_at ? formatDate(p.last_used_at) : 'Never' }}</td>
            <td
              v-if="canWrite"
              class="text-right"
            >
              <ConfirmButton
                label="Remove"
                title="Remove passkey?"
                :message="`“${p.name}” can no longer be used to sign in to this account.`"
                danger
                :action="() => remove(p)"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p
      v-else-if="!error"
      class="muted mt-3 text-sm"
    >
      No passkeys.
    </p>
  </div>
</template>
