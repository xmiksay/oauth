<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ApiError } from '@/api/client'
import { me as meApi } from '@/api/me'
import type { Passkey, PasskeyCreationOptions, Reauth } from '@/api/types'
import { passkeysSupported } from '@/webauthn'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'
import ReauthPrompt from './ReauthPrompt.vue'
import AddPasskeyDialog from './AddPasskeyDialog.vue'

/** The user's passkeys: list, add (re-auth → create), rename inline, remove (re-auth). */
const emit = defineEmits<{ changed: [] }>()

const supported = passkeysSupported()
const passkeys = ref<Passkey[]>([])
const loader = useAction()
const status = ref<string | null>(null)
const addError = ref<unknown>(null)

async function load() {
  const res = await loader.run(() => meApi.passkeys())
  if (res) passkeys.value = res.items
}
onMounted(load)

async function changed(message: string) {
  status.value = message
  await load()
  emit('changed')
}

// `add`: re-auth before creation options; `remove`: re-auth carried by the DELETE.
const prompt = ref<{ kind: 'add' } | { kind: 'remove'; passkey: Passkey } | null>(null)
const creation = ref<PasskeyCreationOptions | null>(null)

const promptText = computed(() =>
  prompt.value?.kind === 'remove'
    ? {
        title: 'Remove passkey?',
        message: `"${prompt.value.passkey.name}" can no longer be used to sign in. Delete it from the device or password manager too.`,
        confirm: 'Remove',
      }
    : { title: 'Add a passkey', message: "Confirm it's you to add a passkey.", confirm: 'Continue' },
)

function open(next: NonNullable<typeof prompt.value>) {
  status.value = null
  addError.value = null
  prompt.value = next
}

async function confirmed(reauth: Reauth) {
  const p = prompt.value
  if (!p) return
  if (p.kind === 'add') {
    try {
      creation.value = await meApi.passkeyOptions(reauth)
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        throw 'You have reached the maximum of 20 passkeys. Remove one first.'
      }
      throw err
    }
    prompt.value = null
    return
  }
  try {
    await meApi.removePasskey(p.passkey.id, reauth)
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      throw "This is your only way to sign in, so it can't be removed. Set a password or add another passkey first."
    }
    throw err
  }
  prompt.value = null
  await changed(`Passkey "${p.passkey.name}" removed.`)
}

function failed(err: unknown) {
  creation.value = null
  addError.value = err
}

async function added(passkey: Passkey) {
  creation.value = null
  await changed(`Passkey "${passkey.name}" added.`)
}

const editing = ref<string | null>(null)
const editName = ref('')
const renamer = useAction()

function startRename(p: Passkey) {
  status.value = null
  renamer.error.value = null
  editing.value = p.id
  editName.value = p.name
}

async function saveRename(p: Passkey) {
  const name = editName.value.trim()
  if (name.length < 1 || name.length > 64) {
    renamer.error.value = 'Use 1 to 64 characters for the name.'
    return
  }
  const updated = await renamer.run(() => meApi.renamePasskey(p.id, name))
  if (!updated) return
  passkeys.value = passkeys.value.map((x) => (x.id === updated.id ? updated : x))
  editing.value = null
}
</script>

<template>
  <section class="card space-y-3">
    <h2 class="text-lg font-semibold">
      Passkeys
    </h2>
    <p class="muted text-sm">
      Sign in with your fingerprint, face, screen lock or a security key instead of a password.
      A passkey also counts as two-step verification.
    </p>
    <ErrorAlert :error="loader.error.value" />
    <div
      v-if="passkeys.length"
      class="overflow-x-auto"
    >
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              Name
            </th>
            <th
              scope="col"
              class="hidden sm:table-cell"
            >
              Added
            </th>
            <th scope="col">
              Last used
            </th>
            <th scope="col">
              <span class="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="p in passkeys"
            :key="p.id"
          >
            <td>
              <form
                v-if="editing === p.id"
                class="flex flex-wrap gap-2"
                @submit.prevent="saveRename(p)"
              >
                <label
                  class="sr-only"
                  :for="`pk-name-${p.id}`"
                >Passkey name</label>
                <input
                  :id="`pk-name-${p.id}`"
                  v-model="editName"
                  class="input max-w-xs"
                  maxlength="64"
                  required
                  autofocus
                >
                <button
                  type="submit"
                  class="btn btn-primary"
                  :disabled="renamer.busy.value"
                >
                  Save
                </button>
                <button
                  type="button"
                  class="btn"
                  @click="editing = null"
                >
                  Cancel
                </button>
              </form>
              <template v-else>
                <span class="font-medium">{{ p.name }}</span>
                <span class="badge ml-1">{{ p.backup_state ? 'Synced' : 'Device-bound' }}</span>
              </template>
            </td>
            <td class="hidden sm:table-cell">
              {{ formatDate(p.created_at) }}
            </td>
            <td>{{ p.last_used_at ? formatDate(p.last_used_at) : 'Never' }}</td>
            <td class="whitespace-nowrap text-right">
              <template v-if="editing !== p.id">
                <button
                  type="button"
                  class="btn-link"
                  @click="startRename(p)"
                >
                  Rename
                </button>
                <button
                  type="button"
                  class="btn-link ml-3 text-red-700 dark:text-red-400"
                  @click="open({ kind: 'remove', passkey: p })"
                >
                  Remove
                </button>
              </template>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p
      v-else-if="!loader.error.value && !loader.busy.value"
      class="text-sm"
    >
      <span class="badge">None</span> You haven't added a passkey yet.
    </p>
    <ErrorAlert :error="renamer.error.value" />
    <ErrorAlert :error="addError" />
    <StatusNote :message="status" />
    <button
      v-if="supported"
      type="button"
      class="btn btn-primary"
      @click="open({ kind: 'add' })"
    >
      Add a passkey
    </button>
    <p
      v-else
      class="muted text-sm"
    >
      This browser can't create passkeys.
    </p>
    <ReauthPrompt
      :open="prompt !== null"
      :title="promptText.title"
      :message="promptText.message"
      :confirm-label="promptText.confirm"
      :danger="prompt?.kind === 'remove'"
      :action="confirmed"
      @close="prompt = null"
    />
    <AddPasskeyDialog
      :options="creation"
      @close="creation = null"
      @added="added"
      @failed="failed"
    />
  </section>
</template>
