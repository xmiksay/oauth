<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { tenants } from '@/api/access'
import type { AdminUserDetail } from '@/api/types'
import { useAction } from '@/composables/useAction'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import UserBadges from '../users/UserBadges.vue'
import ResetPasswordButton from '../users/ResetPasswordButton.vue'
import { hasMfaFactors, RESET_MFA_MESSAGE, resetMfaExplained } from '../users/mfa'

/** One user of another tenant (system host): roles, MFA summary and the two rescue resets. */
const props = defineProps<{ slug: string; userId: string }>()
const emit = defineEmits<{ changed: [] }>()

const user = ref<AdminUserDetail | null>(null)
const loader = useAction()

async function load() {
  const u = await loader.run(() => tenants.user(props.slug, props.userId))
  if (u) user.value = u
}

onMounted(load)

function resetPassword() {
  return tenants.resetPassword(props.slug, props.userId)
}

async function afterPasswordReset() {
  await load()
  emit('changed')
}

async function resetMfa() {
  await resetMfaExplained(() => tenants.resetMfa(props.slug, props.userId))
  await load()
}
</script>

<template>
  <div class="card space-y-4">
    <ErrorAlert :error="loader.error.value" />
    <template v-if="user">
      <div>
        <h2 class="font-semibold">
          {{ user.display_name || user.email }}
        </h2>
        <p class="muted text-sm break-all">
          {{ user.email }}
        </p>
      </div>
      <UserBadges :user="user" />
      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt class="muted">
          Directory roles
        </dt>
        <dd>{{ user.directory_roles.length ? user.directory_roles.join(', ') : 'None' }}</dd>
        <dt class="muted">
          Recovery codes left
        </dt>
        <dd>{{ user.mfa.recovery_codes_remaining }}</dd>
      </dl>
      <div class="flex flex-wrap gap-2">
        <ResetPasswordButton
          :action="resetPassword"
          @reset="afterPasswordReset"
        />
        <ConfirmButton
          label="Reset MFA"
          title="Reset MFA?"
          :message="RESET_MFA_MESSAGE"
          :disabled="!hasMfaFactors(user.mfa)"
          :action="resetMfa"
        />
      </div>
    </template>
  </div>
</template>
