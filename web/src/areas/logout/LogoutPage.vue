<script setup lang="ts">
import { ref } from 'vue'
import { useRoute } from 'vue-router'
import AuthCard from '@/components/AuthCard.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import { authn } from '@/api/authn'
import { useAction } from '@/composables/useAction'

const route = useRoute()
const tenant = String(route.params.tenant ?? '')
// `?signed_out=1` is just a link anyone can craft, so that view still offers the sign-out
// action (a no-op POST when the session is already gone).
const linkSaysSignedOut = route.query.signed_out === '1'
const confirmed = ref(false)
const { busy, error, run } = useAction()

async function signOut() {
  const res = await run(() => authn.signOut(tenant))
  if (res?.signed_out) confirmed.value = true
}
</script>

<template>
  <AuthCard
    :title="confirmed || linkSaysSignedOut ? 'You have been signed out' : 'Sign out?'"
    :tenant="tenant"
  >
    <p
      v-if="confirmed"
      class="muted text-sm"
      aria-live="polite"
    >
      You can close this window. For extra safety, close the browser too.
    </p>
    <div
      v-else
      class="space-y-4"
    >
      <p class="muted text-sm">
        {{
          linkSaysSignedOut
            ? 'You can close this window. Still signed in on this device? Sign out here to be sure.'
            : 'You will be signed out of this account in this browser.'
        }}
      </p>
      <ErrorAlert :error="error" />
      <button
        type="button"
        class="btn w-full"
        :class="{ 'btn-primary': !linkSaysSignedOut }"
        :disabled="busy"
        @click="signOut"
      >
        Sign out
      </button>
    </div>
  </AuthCard>
</template>
