<script setup lang="ts">
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'
import { ApiError } from '@/api/client'
import { authn, type EmailVerified } from '@/api/authn'
import AuthCard from '@/components/AuthCard.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import { INVALID_LINK, linkError, useLinkToken } from './useLinkToken'

/**
 * `/myaccount/verify-email`: confirms an address from an emailed link. Waits for a click
 * instead of POSTing on load — mail scanners open links and would consume the token.
 */
const { slug } = storeToRefs(useTenantStore())
const token = useLinkToken()

const busy = ref(false)
const error = ref<string | null>(token ? null : INVALID_LINK)
const result = ref<EmailVerified | null>(null)
const dead = computed(() => error.value === INVALID_LINK)

const doneText = computed(() => {
  const r = result.value
  if (!r) return ''
  return r.purpose === 'change'
    ? `Your sign-in email is now ${r.email}.`
    : `Your email address ${r.email} is verified.`
})

async function confirm() {
  if (!token || busy.value) return
  busy.value = true
  error.value = null
  try {
    result.value = await authn.verifyEmail(token)
  } catch (err) {
    error.value =
      err instanceof ApiError && err.status === 409
        ? 'That address is now used by another account, so your email was not changed.'
        : linkError(err)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <AuthCard
    :title="result ? 'Email address confirmed' : 'Confirm email address'"
    :tenant="slug"
  >
    <div
      v-if="result"
      class="space-y-4"
      aria-live="polite"
    >
      <p class="text-sm">
        {{ doneText }}
      </p>
      <RouterLink
        :to="{ name: 'myaccount' }"
        class="btn-link"
      >
        Go to My Account
      </RouterLink>
    </div>
    <div
      v-else
      class="space-y-4"
    >
      <p
        v-if="!dead"
        class="muted text-sm"
      >
        Confirm that this email address belongs to you.
      </p>
      <ErrorAlert :error="error" />
      <button
        v-if="!dead"
        type="button"
        class="btn btn-primary w-full"
        :disabled="busy"
        @click="confirm"
      >
        Confirm email address
      </button>
    </div>
  </AuthCard>
</template>
