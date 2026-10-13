<script setup lang="ts">
import type { Session } from '@/api/types'
import { formatDate } from '@/lib/format'

/** Sessions with an optional per-row action (slot `action`). */
defineProps<{ sessions: Session[] }>()
</script>

<template>
  <div class="overflow-x-auto">
    <table class="table">
      <thead>
        <tr>
          <th scope="col">
            Device
          </th>
          <th scope="col">
            Signed in
          </th>
          <th
            scope="col"
            class="hidden sm:table-cell"
          >
            Expires
          </th>
          <th
            v-if="$slots.action"
            scope="col"
          >
            <span class="sr-only">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="s in sessions"
          :key="s.id"
        >
          <td>
            <span class="block max-w-xs truncate sm:max-w-md">{{ s.user_agent || 'Unknown device' }}</span>
            <span class="muted text-xs">{{ s.ip || 'unknown IP' }} · {{ s.amr.join(', ') }}</span>
            <span
              v-if="s.current"
              class="badge ml-1"
            >This session</span>
          </td>
          <td>{{ formatDate(s.auth_time) }}</td>
          <td class="hidden sm:table-cell">
            {{ formatDate(s.expires_at) }}
          </td>
          <td v-if="$slots.action">
            <slot
              name="action"
              :session="s"
            />
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
