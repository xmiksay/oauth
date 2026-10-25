<script setup lang="ts">
import { ref } from 'vue'
import type { PasswordReset } from '@/api/directory'
import ConfirmButton from '@/components/ConfirmButton.vue'
import SecretOnceDialog from '@/components/SecretOnceDialog.vue'

/** "Reset password" for an admin: confirm, run `action`, show the temporary password once. */
const props = defineProps<{ action: () => Promise<PasswordReset> }>()
const emit = defineEmits<{ reset: [] }>()

// Secret-once: only in this instance's ref, cleared when the dialog closes.
const oneTime = ref<string[] | null>(null)

async function run() {
  const res = await props.action()
  if (res.one_time_password) oneTime.value = [res.one_time_password]
  emit('reset')
}
</script>

<template>
  <ConfirmButton
    label="Reset password"
    title="Reset password?"
    message="A new temporary password is generated and shown once. All of the user's sessions end."
    :action="run"
  />
  <SecretOnceDialog
    title="Temporary password"
    description="Give this password to the user. They must change it at their next sign-in."
    :values="oneTime"
    @close="oneTime = null"
  />
</template>
