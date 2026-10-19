<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { me as meApi } from '@/api/me'
import type { IdpRef, MyIdentities, MyIdentity, Reauth } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import { isWebUrl, navigateTo } from '@/lib/navigate'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'
import ReauthPrompt from './ReauthPrompt.vue'

/**
 * Accounts at external identity providers: link (re-auth → the provider's sign-in page; the
 * server links on the way back and returns here with `?federation=…`) and unlink (re-auth).
 * Hidden while there is nothing to link or show.
 */
const LINK_FAILED = 'Linking failed. Please try again.'
const LINK_ERRORS: Record<string, string> = {
  already_linked:
    'This identity is already linked to an account, or you already linked an account of this provider.',
  account_disabled: 'This account is disabled.',
  session_ended: 'Your session ended before linking finished. Sign in again and retry.',
}

const route = useRoute()
const router = useRouter()
const data = ref<MyIdentities | null>(null)
const loader = useAction()
const note = ref<string | null>(null)
const linkError = ref<string | null>(null)
const prompt = ref<{ link: IdpRef } | { unlink: MyIdentity } | null>(null)

async function load() {
  const res = await loader.run(meApi.identities)
  if (res) data.value = res
}

/** "Linked Entra (ann@contoso.com)": the newest link is the one that just finished. */
function linkedNote(items: MyIdentity[]): string {
  const newest = items.reduce<MyIdentity | null>(
    (best, i) => (!best || Date.parse(i.linked_at) > Date.parse(best.linked_at) ? i : best),
    null,
  )
  if (!newest) return 'Account linked.'
  return `Linked ${newest.idp_name}${newest.email ? ` (${newest.email})` : ''}`
}

/**
 * The outcome the server's redirect reported (dropped from the URL so a reload is quiet);
 * `true` for a finished link.
 */
function takeOutcome(): boolean {
  const { federation, federation_error, ...rest } = route.query
  if (typeof federation_error === 'string') {
    linkError.value = LINK_ERRORS[federation_error] ?? LINK_FAILED
  }
  if (federation !== undefined || federation_error !== undefined) {
    void router.replace({ query: rest })
  }
  return federation === 'linked'
}

onMounted(async () => {
  const linked = takeOutcome()
  await load()
  if (linked) note.value = linkedNote(data.value?.items ?? [])
})

const visible = computed(
  () =>
    !!loader.error.value ||
    !!note.value ||
    !!linkError.value ||
    !!(data.value && (data.value.items.length || data.value.available.length)),
)

const promptText = computed(() => {
  const p = prompt.value
  if (p && 'unlink' in p) {
    return {
      title: `Unlink ${p.unlink.idp_name}?`,
      message: `You can no longer sign in with this ${p.unlink.idp_name} account.`,
      confirm: 'Unlink',
    }
  }
  const name = p?.link.name ?? ''
  return {
    title: `Link ${name}`,
    message: `Confirm it's you, then sign in at ${name} to link that account.`,
    confirm: 'Continue',
  }
})

function open(next: { link: IdpRef } | { unlink: MyIdentity }) {
  note.value = null
  linkError.value = null
  prompt.value = next
}

async function confirmed(reauth: Reauth) {
  const p = prompt.value
  if (!p) return
  if ('unlink' in p) {
    // A 409 (the last way to sign in) carries the server's explanation; the prompt shows it.
    await meApi.unlinkIdentity(p.unlink.id, reauth)
    prompt.value = null
    note.value = `${p.unlink.idp_name} unlinked.`
    await load()
    return
  }
  const { redirect } = await meApi.linkIdentity(p.link.id, reauth)
  if (!isWebUrl(redirect)) throw 'The server returned an invalid address. Contact your administrator.'
  prompt.value = null
  note.value = `Redirecting to ${p.link.name}…`
  navigateTo(redirect)
}
</script>

<template>
  <section
    v-if="visible"
    class="card space-y-3"
  >
    <h2 class="text-lg font-semibold">
      Linked accounts
    </h2>
    <p class="muted text-sm">
      Sign in with an account you have at another identity provider.
    </p>
    <ErrorAlert :error="loader.error.value" />
    <ErrorAlert :error="linkError" />
    <StatusNote :message="note" />
    <ul
      v-if="data?.items.length"
      class="divide-y divide-gray-200 dark:divide-gray-800"
    >
      <li
        v-for="i in data.items"
        :key="i.id"
        class="flex flex-wrap items-center justify-between gap-2 py-2"
      >
        <div class="text-sm">
          <p class="font-medium">
            {{ i.idp_name }}
          </p>
          <p class="muted">
            {{ i.email ?? 'No email shared' }} · linked {{ formatDate(i.linked_at) }} · last used
            {{ i.last_used_at ? formatDate(i.last_used_at) : 'never' }}
          </p>
        </div>
        <button
          type="button"
          class="btn text-red-700 dark:text-red-400"
          @click="open({ unlink: i })"
        >
          Unlink
        </button>
      </li>
    </ul>
    <div
      v-if="data?.available.length"
      class="flex flex-wrap gap-2"
    >
      <button
        v-for="idp in data.available"
        :key="idp.id"
        type="button"
        class="btn"
        @click="open({ link: idp })"
      >
        Link {{ idp.name }}
      </button>
    </div>
    <ReauthPrompt
      :open="prompt !== null"
      :title="promptText.title"
      :message="promptText.message"
      :confirm-label="promptText.confirm"
      :danger="!!prompt && 'unlink' in prompt"
      :action="confirmed"
      @close="prompt = null"
    />
  </section>
</template>
