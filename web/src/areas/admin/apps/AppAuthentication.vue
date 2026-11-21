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
const saved = ref(false)
const { busy, error, run } = useAction()

watchEffect(() => {
  redirects.value = (app.value?.redirect_uris ?? []).join('\n')
  postLogout.value = (app.value?.post_logout_redirect_uris ?? []).join('\n')
  origins.value = (app.value?.web_origins ?? []).join('\n')
})

async function save() {
  saved.value = false
  const ok = await run(() =>
    store.update({
      redirect_uris: parseLines(redirects.value),
      post_logout_redirect_uris: parseLines(postLogout.value),
      web_origins: parseLines(origins.value),
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
