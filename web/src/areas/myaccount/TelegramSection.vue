<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ApiError } from '@/api/client'
import { me as meApi } from '@/api/me'
import type { Reauth, TelegramLink, TelegramStatus } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'
import ReauthPrompt from './ReauthPrompt.vue'

/**
 * Links a Telegram chat: re-auth → a single-use bot deep link → the user presses Start in
 * Telegram while this polls `GET me/telegram`. Unlink takes a re-auth too.
 */
const emit = defineEmits<{ changed: [] }>()

const POLL_MS = 3000

const status = ref<TelegramStatus | null>(null)
const loader = useAction()
const note = ref<string | null>(null)
const expired = ref(false)
const prompt = ref<'link' | 'unlink' | null>(null)
// The deep link carries a bearer code: component state only, dropped once done or cancelled.
const link = ref<TelegramLink | null>(null)
let poll: ReturnType<typeof setTimeout> | null = null

async function load() {
  const res = await loader.run(() => meApi.getTelegram())
  if (res) status.value = res
}
onMounted(load)

function stopPolling() {
  if (poll !== null) clearTimeout(poll)
  poll = null
}
function cancel() {
  stopPolling()
  link.value = null
}

// A poll answered after unmount must not re-arm the timer.
let disposed = false
onUnmounted(() => {
  disposed = true
  cancel()
})

function schedule() {
  if (disposed) return
  poll = setTimeout(check, POLL_MS)
}

async function check() {
  poll = null
  const current = link.value
  if (!current) return
  if (Date.now() >= Date.parse(current.expires_at)) {
    cancel()
    expired.value = true
    return
  }
  try {
    const res = await meApi.getTelegram()
    // Cancelled (or replaced by a new link) while the request was in flight.
    if (link.value !== current) return
    if (res.linked) {
      cancel()
      status.value = res
      note.value = 'Telegram linked.'
      emit('changed')
      return
    }
  } catch {
    // A transient failure: keep waiting until the link expires.
    if (link.value !== current) return
  }
  schedule()
}

const promptText = computed(() =>
  prompt.value === 'unlink'
    ? {
        title: 'Unlink Telegram?',
        message:
          'Sign-in will no longer offer codes via Telegram, and Telegram notifications stop.',
        confirm: 'Unlink',
      }
    : { title: 'Link Telegram', message: "Confirm it's you to link Telegram.", confirm: 'Continue' },
)

function open(kind: 'link' | 'unlink') {
  note.value = null
  expired.value = false
  prompt.value = kind
}

async function confirmed(reauth: Reauth) {
  if (prompt.value === 'unlink') {
    try {
      await meApi.unlinkTelegram(reauth)
    } catch (err) {
      // 404: already unlinked (e.g. in another tab) — the outcome the user asked for.
      if (!(err instanceof ApiError && err.status === 404)) throw err
    }
    prompt.value = null
    status.value = { linked: false, username: null, linked_at: null }
    note.value = 'Telegram unlinked.'
    emit('changed')
    return
  }
  cancel()
  const res = await meApi.linkTelegram(reauth)
  prompt.value = null
  link.value = res
  window.open(res.url, '_blank', 'noopener,noreferrer')
  schedule()
}

const linkedLabel = computed(() => {
  const s = status.value
  if (!s) return ''
  const who = s.username ? `Linked to @${s.username}` : 'Linked'
  return s.linked_at ? `${who} since ${formatDate(s.linked_at)}.` : `${who}.`
})

const expiresAt = computed(() =>
  link.value
    ? new Date(link.value.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : '',
)
</script>

<template>
  <section class="card space-y-3">
    <h2 class="text-lg font-semibold">
      Telegram
    </h2>
    <p class="muted text-sm">
      Get security notifications from our Telegram bot. Once linked, sign-in may also ask for a
      code sent to you via Telegram.
    </p>
    <ErrorAlert :error="loader.error.value" />
    <div
      v-if="link"
      class="space-y-2 rounded-md border border-gray-300 px-3 py-2 dark:border-gray-700"
      data-testid="telegram-pending"
    >
      <p class="text-sm font-medium">
        Open Telegram and press Start.
      </p>
      <p class="muted text-sm">
        Telegram didn't open?
        <a
          :href="link.url"
          target="_blank"
          rel="noopener noreferrer"
          class="btn-link"
        >Open the link to our bot</a>. It works once, until {{ expiresAt }}.
      </p>
      <p
        class="muted text-sm"
        aria-live="polite"
      >
        Waiting for Telegram…
      </p>
      <button
        type="button"
        class="btn"
        @click="cancel"
      >
        Cancel
      </button>
    </div>
    <template v-else-if="status">
      <p
        v-if="status.linked"
        class="text-sm"
      >
        <span class="badge">On</span> {{ linkedLabel }}
      </p>
      <p
        v-else
        class="text-sm"
      >
        <span class="badge">Off</span> Not linked.
      </p>
      <p
        v-if="expired"
        role="alert"
        class="text-sm text-red-700 dark:text-red-400"
      >
        The link expired — try again.
      </p>
      <StatusNote :message="note" />
      <button
        v-if="status.linked"
        type="button"
        class="btn text-red-700 dark:text-red-400"
        @click="open('unlink')"
      >
        Unlink
      </button>
      <button
        v-else
        type="button"
        class="btn btn-primary"
        @click="open('link')"
      >
        Link Telegram
      </button>
    </template>
    <ReauthPrompt
      :open="prompt !== null"
      :title="promptText.title"
      :message="promptText.message"
      :confirm-label="promptText.confirm"
      :danger="prompt === 'unlink'"
      :action="confirmed"
      @close="prompt = null"
    />
  </section>
</template>
