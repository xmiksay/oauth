<script setup lang="ts">
import { computed, ref, watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useApplicationStore } from '@/stores/application'
import { useAction } from '@/composables/useAction'
import { parseLines } from '@/lib/format'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'

const store = useApplicationStore()
const { app, canEditConfig } = storeToRefs(store)
const redirects = ref('')
const postLogout = ref('')
const origins = ref('')
/** Origins granted only through the redirect URIs (public clients), shown read-only. */
const derivedOrigins = computed(() =>
  (app.value?.effective_web_origins ?? []).filter((o) => !app.value?.web_origins.includes(o)),
)
const deviceCode = ref(false)
const backchannelUri = ref('')
const backchannelSid = ref(false)
const hasBackchannel = computed(() => backchannelUri.value.trim() !== '')
const saved = ref(false)
const { busy, error, run } = useAction()

watchEffect(() => {
  redirects.value = (app.value?.redirect_uris ?? []).join('\n')
  postLogout.value = (app.value?.post_logout_redirect_uris ?? []).join('\n')
  origins.value = (app.value?.web_origins ?? []).join('\n')
  deviceCode.value = app.value?.device_code_enabled ?? false
  backchannelUri.value = app.value?.backchannel_logout_uri ?? ''
  backchannelSid.value = app.value?.backchannel_logout_session_required ?? false
})

async function save() {
  saved.value = false
  const ok = await run(() =>
    store.update({
      redirect_uris: parseLines(redirects.value),
      post_logout_redirect_uris: parseLines(postLogout.value),
      web_origins: parseLines(origins.value),
      device_code_enabled: deviceCode.value,
      backchannel_logout_uri: backchannelUri.value.trim() || null,
      // Meaningless without a URI: clearing the URI clears the flag.
      backchannel_logout_session_required: hasBackchannel.value && backchannelSid.value,
    }),
  )
  saved.value = !!ok
}
</script>

<template>
  <form
    v-if="app"
    class="card max-w-3xl space-y-5"
    @submit.prevent="save"
    @input="saved = false"
  >
    <div>
      <label
        class="label"
        for="aa-redirects"
      >Redirect URIs</label>
      <textarea
        id="aa-redirects"
        v-model="redirects"
        class="input font-mono"
        rows="5"
        :disabled="!canEditConfig"
        aria-describedby="aa-hint"
      />
      <p
        id="aa-hint"
        class="hint"
      >
        One per line, up to 32. Absolute https:// URIs, or http://127.0.0.1 / http://[::1]
        (registered without a port; any port matches). No fragments; http://localhost is not
        allowed.
      </p>
    </div>
    <div>
      <label
        class="label"
        for="aa-logout"
      >Sign-out redirect URIs (post_logout_redirect_uri)</label>
      <textarea
        id="aa-logout"
        v-model="postLogout"
        class="input font-mono"
        rows="3"
        :disabled="!canEditConfig"
      />
      <p class="hint">
        Where the app may send users after sign-out (post_logout_redirect_uri). Same rules.
      </p>
    </div>
    <div>
      <label
        class="label"
        for="aa-origins"
      >Allowed web origins (CORS)</label>
      <textarea
        id="aa-origins"
        v-model="origins"
        class="input font-mono"
        rows="3"
        :disabled="!canEditConfig"
        aria-describedby="aa-origins-hint"
      />
      <p
        id="aa-origins-hint"
        class="hint"
      >
        Browser origins that may call the token, revoke, userinfo, discovery and JWKS endpoints
        from another host. One per line, up to 32, exactly scheme://host[:port]: https://, or
        http://127.0.0.1 / http://[::1]; lowercase, no path, trailing slash or wildcard.
      </p>
      <p
        v-if="derivedOrigins.length"
        class="hint"
        data-testid="derived-origins"
      >
        Also allowed through the redirect URIs (public client):
        <span class="font-mono">{{ derivedOrigins.join(', ') }}</span>
      </p>
    </div>
    <label class="flex items-start gap-2 text-sm">
      <input
        id="aa-device"
        v-model="deviceCode"
        type="checkbox"
        class="mt-1"
        :disabled="!canEditConfig"
      >
      <span>
        <span class="font-medium">Allow the device code flow</span>
        <span class="muted block">For devices without a usable browser (TVs, command-line tools):
          the device shows a code that the user enters at /device on this tenant's sign-in host
          (RFC 8628). Needs no redirect URI.</span>
      </span>
    </label>
    <div>
      <label
        class="label"
        for="aa-backchannel"
      >Back-channel logout URI</label>
      <input
        id="aa-backchannel"
        v-model="backchannelUri"
        class="input font-mono"
        :disabled="!canEditConfig"
        aria-describedby="aa-backchannel-hint"
      >
      <p
        id="aa-backchannel-hint"
        class="hint"
      >
        OpenID Connect Back-Channel Logout: when a session in which the app obtained tokens
        ends, a signed logout token (with sid and sub) is POSTed here. Absolute https:// URL,
        no fragment; must reach a public address. Leave empty to turn it off.
      </p>
      <label class="mt-2 flex items-start gap-2 text-sm">
        <input
          id="aa-backchannel-sid"
          v-model="backchannelSid"
          type="checkbox"
          class="mt-1"
          :disabled="!canEditConfig || !hasBackchannel"
          aria-describedby="aa-backchannel-sid-hint"
        >
        <span>
          The app requires the session id (sid) in logout tokens
          <span
            id="aa-backchannel-sid-hint"
            class="hint block"
          >Recorded for the app's registration only: logout tokens always carry sid.</span>
        </span>
      </label>
    </div>
    <ErrorAlert :error="error" />
    <StatusNote :message="saved ? 'Saved.' : null" />
    <button
      v-if="canEditConfig"
      type="submit"
      class="btn btn-primary"
      :disabled="busy"
    >
      Save
    </button>
  </form>
</template>
