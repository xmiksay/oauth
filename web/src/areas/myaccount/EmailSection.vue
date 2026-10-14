<script setup lang="ts">
import { ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { ApiError } from '@/api/client'
import { me as meApi } from '@/api/me'
import type { Reauth } from '@/api/types'
import { useAction } from '@/composables/useAction'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'
import ReauthPrompt from './ReauthPrompt.vue'

/** The sign-in address: verification status, a new verification link, and changing it. */
const auth = useAuthStore()
const { me } = storeToRefs(auth)
const status = ref<string | null>(null)
const verify = useAction()

async function sendVerification() {
  status.value = null
  const res = await verify.run(() =>
    meApi.sendVerification().catch(async (err: unknown) => {
      // Verified meanwhile (another tab, or the link was just opened): show the truth.
      if (err instanceof ApiError && err.status === 409) {
        auth.setMe(await meApi.get())
        return null
      }
      throw err
    }),
  )
  if (res) status.value = `Check your inbox: we sent a verification link to ${me.value?.email}.`
}

const changing = ref(false)
const newEmail = ref('')

function openChange() {
  newEmail.value = ''
  status.value = null
  changing.value = true
}

async function changeEmail(reauth: Reauth) {
  const address = newEmail.value.trim()
  if (!address) throw 'Enter the new email address.'
  try {
    await meApi.changeEmail(address, reauth)
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      throw 'That email address is already used by another account.'
    }
    throw err
  }
  changing.value = false
  status.value = `We sent a link to ${address}. Your email changes when you open it.`
}
</script>

<template>
  <section
    v-if="me"
    class="card space-y-4"
  >
    <h2 class="text-lg font-semibold">
      Email
    </h2>
    <p class="flex flex-wrap items-center gap-2 text-sm">
      <span class="break-all">{{ me.email }}</span>
      <span
        class="badge"
        data-testid="email-status"
      >{{ me.email_verified ? 'Verified' : 'Unverified' }}</span>
    </p>
    <p
      v-if="!me.email_verified && me.features.email"
      class="muted text-sm"
    >
      Verify your address so we can send you security notifications.
    </p>
    <ErrorAlert :error="verify.error.value" />
    <StatusNote :message="status" />
    <div
      v-if="me.features.email"
      class="flex flex-wrap gap-2"
    >
      <button
        v-if="!me.email_verified"
        type="button"
        class="btn btn-primary"
        :disabled="verify.busy.value"
        @click="sendVerification"
      >
        Send verification link
      </button>
      <button
        type="button"
        class="btn"
        @click="openChange"
      >
        Change email
      </button>
    </div>
    <ReauthPrompt
      :open="changing"
      title="Change email"
      message="We'll send a link to the new address. Your sign-in email changes when you open it."
      confirm-label="Send link"
      :action="changeEmail"
      @close="changing = false"
    >
      <div>
        <label
          class="label"
          for="ce-email"
        >New email</label>
        <input
          id="ce-email"
          v-model="newEmail"
          class="input"
          type="email"
          autocomplete="email"
          required
          autofocus
        >
      </div>
    </ReauthPrompt>
  </section>
</template>
