<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { identityProviders } from '@/api/identityProviders'
import type {
  IdentityProviderDetail,
  IdentityProviderInput,
  IdentityProviderPatch,
} from '@/api/types'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import PageHeader from '@/components/PageHeader.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import CopyButton from '@/components/CopyButton.vue'
import ModalDialog from '@/components/ModalDialog.vue'
import IdpForm from './IdpForm.vue'
import { POLICY_LABELS, changedIdpFields, lockoutWarning, relinkWarning } from './idpForm'

const route = useRoute()
const router = useRouter()
const id = String(route.params.id)
const { isGlobalAdmin } = storeToRefs(useAuthStore())

const idp = ref<IdentityProviderDetail | null>(null)
const loader = useAction()
const saver = useAction()
const saved = ref(false)
// Re-mounts the form after each save, which also drops a typed secret.
const formVersion = ref(0)

function show(next: IdentityProviderDetail) {
  idp.value = next
  formVersion.value++
}

onMounted(async () => {
  const res = await loader.run(() => identityProviders.get(id))
  if (res) show(res)
})

const lockout = computed(() => lockoutWarning(idp.value?.users_only_via ?? 0))
const withLockout = (message: string) => (lockout.value ? `${message} ${lockout.value}` : message)

// A save waiting for "unlinks everyone" to be confirmed; may hold a typed secret, so it stays
// in this component and is dropped on cancel.
const pending = ref<{ diff: IdentityProviderPatch; warning: string } | null>(null)

async function apply(diff: IdentityProviderPatch) {
  pending.value = null
  if (Object.keys(diff).length > 0) {
    const res = await saver.run(() => identityProviders.update(id, diff))
    if (!res) return
    show(res)
  }
  saved.value = true
}

async function save(body: IdentityProviderInput) {
  const current = idp.value
  if (!current) return
  saved.value = false
  const diff = changedIdpFields(current, body)
  const warning = relinkWarning(diff, current.linked_users, current.has_secret)
  if (warning) pending.value = { diff, warning }
  else await apply(diff)
}

async function setEnabled(enabled: boolean) {
  show(await identityProviders.update(id, { enabled }))
}

async function remove() {
  await identityProviders.remove(id)
  await router.replace({ name: 'admin-identity-providers' })
}
</script>

<template>
  <section>
    <PageHeader
      :title="idp?.name ?? 'Identity provider'"
      :description="idp?.issuer"
    >
      <template #breadcrumb>
        <RouterLink
          :to="{ name: 'admin-identity-providers' }"
          class="btn-link"
        >
          Identity providers
        </RouterLink>
      </template>
      <template
        v-if="isGlobalAdmin && idp"
        #actions
      >
        <ConfirmButton
          :label="idp.enabled ? 'Disable' : 'Enable'"
          :title="idp.enabled ? 'Disable identity provider?' : 'Enable identity provider?'"
          :message="
            idp.enabled
              ? withLockout(`Users can no longer sign in with ${idp.name}.`)
              : `Users can sign in with ${idp.name} again.`
          "
          :danger="idp.enabled"
          :action="() => setEnabled(!idp?.enabled)"
        />
        <ConfirmButton
          label="Delete"
          title="Delete identity provider?"
          :message="withLockout(`${idp.name} and all identities linked to it are deleted.`)"
          danger
          :action="remove"
        />
      </template>
    </PageHeader>
    <ErrorAlert :error="loader.error.value" />
    <template v-if="idp">
      <p class="mb-4 flex flex-wrap gap-1">
        <span class="badge">{{ idp.enabled ? 'Enabled' : 'Disabled' }}</span>
        <span class="badge">{{ idp.visible ? 'Shown on sign-in page' : 'Hidden' }}</span>
        <span class="badge">{{ POLICY_LABELS[idp.policy] }}</span>
        <span class="badge">{{ idp.has_secret ? 'Secret set' : 'No secret' }}</span>
      </p>
      <p
        v-if="lockout"
        role="note"
        class="mb-4 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
        data-testid="lockout"
      >
        {{ lockout }}
      </p>
      <div class="grid gap-4 xl:grid-cols-2">
        <div class="card space-y-4">
          <h2 class="font-semibold">
            Configuration
          </h2>
          <IdpForm
            :key="formVersion"
            form-id="edit-idp"
            :initial="idp"
            :readonly="!isGlobalAdmin"
            @submit="save"
            @input="saved = false"
          />
          <ErrorAlert :error="saver.error.value" />
          <StatusNote :message="saved ? 'Saved.' : null" />
          <button
            v-if="isGlobalAdmin"
            type="submit"
            form="edit-idp"
            class="btn btn-primary"
            :disabled="saver.busy.value"
          >
            Save
          </button>
        </div>
        <div class="card h-fit space-y-3">
          <h2 class="font-semibold">
            Redirect URI
          </h2>
          <p class="muted text-sm">
            Register this redirect URI at the identity provider.
          </p>
          <p
            class="mono break-all text-sm"
            data-testid="redirect-uri"
          >
            {{ idp.redirect_uri }}
          </p>
          <CopyButton :text="idp.redirect_uri" />
          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt class="muted">
              Object ID
            </dt>
            <dd class="mono">
              {{ idp.id }}
            </dd>
            <dt class="muted">
              Created
            </dt>
            <dd>{{ formatDate(idp.created_at) }}</dd>
            <dt class="muted">
              Linked users
            </dt>
            <dd data-testid="linked-users">
              {{ idp.linked_users }}
            </dd>
            <dt class="muted">
              Users only signing in here
            </dt>
            <dd>{{ idp.users_only_via }}</dd>
          </dl>
        </div>
      </div>
    </template>
    <ModalDialog
      :open="pending !== null"
      title="Unlink all users?"
      @close="pending = null"
    >
      <p class="text-sm">
        {{ pending?.warning }}
      </p>
      <template #actions>
        <button
          type="button"
          class="btn"
          @click="pending = null"
        >
          Cancel
        </button>
        <button
          type="button"
          class="btn btn-danger"
          :disabled="saver.busy.value"
          @click="pending && apply(pending.diff)"
        >
          Save and unlink
        </button>
      </template>
    </ModalDialog>
  </section>
</template>
