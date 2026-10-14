<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import type { Reauth } from '@/api/types'
import { passkeysSupported } from '@/webauthn'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import { passkeyReauth, reauthError, type ReauthMethod } from './reauth'

/**
 * Re-authenticates before a security-info change — with the current password (when the user
 * has one) or a passkey (when they have one) — then runs `action`.
 * The default slot adds fields above it (their state stays with the caller).
 */
const props = defineProps<{
  open: boolean
  title: string
  message: string
  confirmLabel: string
  danger?: boolean
  action: (reauth: Reauth) => Promise<unknown>
}>()
const emit = defineEmits<{ close: [] }>()

const { me } = storeToRefs(useAuthStore())
const withPassword = computed(() => me.value?.has_password ?? true)
const withPasskey = computed(() => (me.value?.mfa.passkeys ?? 0) > 0 && passkeysSupported())

const form = ref<HTMLFormElement | null>(null)
const password = ref('')
const busy = ref(false)
const error = ref<unknown>(null)

watch(
  () => props.open,
  () => {
    password.value = ''
    error.value = null
  },
)

async function attempt(via: ReauthMethod, reauth: () => Promise<Reauth>) {
  busy.value = true
  error.value = null
  try {
    await props.action(await reauth())
  } catch (err) {
    error.value = reauthError(err, via)
  } finally {
    busy.value = false
    password.value = ''
  }
}

function usePasskey() {
  // The slot's fields (e.g. a new email) must be valid before the passkey dialog opens.
  if (form.value && !form.value.reportValidity()) return
  void attempt('passkey', passkeyReauth)
}

function submit() {
  if (withPassword.value) void attempt('password', async () => ({ password: password.value }))
  else usePasskey()
}
</script>

<template>
  <ModalDialog
    :open="open"
    :title="title"
    @close="emit('close')"
  >
    <form
      id="reauth-prompt"
      ref="form"
      class="space-y-4"
      @submit.prevent="submit"
    >
      <p class="text-sm">
        {{ message }}
      </p>
      <slot />
      <div v-if="withPassword">
        <label
          class="label"
          for="pp-password"
        >Current password</label>
        <!-- Not `required`: "Use a passkey instead" validates the form without it. -->
        <input
          id="pp-password"
          v-model="password"
          class="input"
          type="password"
          autocomplete="current-password"
          autofocus
        >
      </div>
      <p
        v-else-if="withPasskey"
        class="muted text-sm"
      >
        You'll confirm with one of your passkeys.
      </p>
      <p
        v-else
        role="alert"
        class="text-sm"
      >
        Your account signs in only with passkeys, and this browser can't use them. Use a
        browser or device that supports passkeys.
      </p>
      <ErrorAlert :error="error" />
    </form>
    <template #actions>
      <button
        type="button"
        class="btn"
        @click="emit('close')"
      >
        Cancel
      </button>
      <button
        v-if="withPassword && withPasskey"
        type="button"
        class="btn"
        :disabled="busy"
        @click="usePasskey"
      >
        Use a passkey instead
      </button>
      <button
        v-if="withPassword || withPasskey"
        type="submit"
        form="reauth-prompt"
        class="btn"
        :class="danger ? 'btn-danger' : 'btn-primary'"
        :disabled="busy || (withPassword && !password)"
      >
        {{ confirmLabel }}
      </button>
    </template>
  </ModalDialog>
</template>
