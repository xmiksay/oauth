<script setup lang="ts">
import { ref, watch } from 'vue'
import { ApiError } from '@/api/client'
import { me as meApi } from '@/api/me'
import type { Passkey, PasskeyCreationOptions } from '@/api/types'
import { PasskeyCancelled, createPasskey } from '@/webauthn'
import { useAction } from '@/composables/useAction'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'

/**
 * Second step of adding a passkey, after re-authentication handed over `options`. Its own
 * click starts `navigator.credentials.create`: some browsers allow one WebAuthn call per user
 * gesture, and a passkey re-authentication already used it.
 */
const props = defineProps<{ options: PasskeyCreationOptions | null }>()
const emit = defineEmits<{ close: []; added: [passkey: Passkey]; failed: [error: unknown] }>()

const name = ref('')
const { busy, error, run } = useAction()

watch(
  () => props.options,
  () => {
    name.value = ''
    error.value = null
  },
)

function registrationError(err: unknown): unknown {
  if (!(err instanceof ApiError)) return err
  if (err.status === 409) {
    return 'This passkey is already registered, or you have reached the maximum of 20 passkeys.'
  }
  return err.code === 'invalid_request' ? "That passkey couldn't be registered." : err
}

/**
 * Only a dismissed browser dialog keeps these options: the server consumed their challenge on
 * any other outcome, and retrying with them would leave a credential on the authenticator that
 * can never be registered. Anything else closes; the user re-authenticates for fresh options.
 */
async function create() {
  const options = props.options
  if (!options) return
  const added = await run(async () => {
    try {
      const credential = await createPasskey(options)
      return await meApi.addPasskey(credential, name.value.trim() || undefined)
    } catch (err) {
      if (err instanceof PasskeyCancelled) throw err
      emit('failed', registrationError(err))
      return undefined
    }
  })
  if (added) emit('added', added)
}
</script>

<template>
  <ModalDialog
    :open="options !== null"
    title="Add a passkey"
    @close="emit('close')"
  >
    <form
      id="add-passkey"
      class="space-y-4"
      @submit.prevent="create"
    >
      <p class="text-sm">
        Your browser asks where to save the passkey: this device, a password manager or a
        security key. Afterwards you can sign in with it instead of a password.
      </p>
      <div>
        <label
          class="label"
          for="ap-name"
        >Name (optional)</label>
        <input
          id="ap-name"
          v-model="name"
          class="input"
          maxlength="64"
          placeholder="e.g. Work laptop"
          autocomplete="off"
        >
      </div>
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
        type="submit"
        form="add-passkey"
        class="btn btn-primary"
        :disabled="busy"
      >
        Create passkey
      </button>
    </template>
  </ModalDialog>
</template>
