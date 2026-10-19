<script setup lang="ts">
import { ApiError } from '@/api/client'
import { users } from '@/api/directory'
import type { UserIdentity } from '@/api/types'
import { formatDate } from '@/lib/format'
import ConfirmButton from '@/components/ConfirmButton.vue'

/** Upstream identities linked to a user (from `GET users/{id}`); `canWrite` adds unlink. */
const props = defineProps<{ userId: string; identities: UserIdentity[]; canWrite: boolean }>()
const emit = defineEmits<{ changed: [] }>()

async function unlink(identity: UserIdentity) {
  try {
    await users.unlinkIdentity(props.userId, identity.id)
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      throw (
        err.description ??
        "This is the user's only way to sign in. Set a password first (reset password), then unlink it."
      )
    }
    throw err
  }
  emit('changed')
}
</script>

<template>
  <div class="card">
    <h2 class="font-semibold">
      Linked identities
    </h2>
    <div
      v-if="identities.length"
      class="mt-3 overflow-x-auto"
    >
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              Provider
            </th>
            <th scope="col">
              Identity
            </th>
            <th
              scope="col"
              class="hidden sm:table-cell"
            >
              Linked
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
            v-for="i in identities"
            :key="i.id"
          >
            <td>{{ i.idp_name }}</td>
            <td>
              {{ i.email ?? '—' }}
              <span class="mono muted block text-xs break-all">{{ i.subject }}</span>
            </td>
            <td class="hidden sm:table-cell">
              {{ formatDate(i.linked_at) }}
            </td>
            <td>{{ i.last_used_at ? formatDate(i.last_used_at) : 'Never' }}</td>
            <td
              v-if="canWrite"
              class="text-right"
            >
              <ConfirmButton
                label="Unlink"
                title="Unlink identity?"
                :message="`The user can no longer sign in with this ${i.idp_name} account.`"
                danger
                :action="() => unlink(i)"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p
      v-else
      class="muted mt-3 text-sm"
    >
      No linked identities.
    </p>
  </div>
</template>
