<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { identityProviders } from '@/api/identityProviders'
import type { IdentityProvider, IdentityProviderInput } from '@/api/types'
import { usePagedList } from '@/composables/usePagedList'
import { useAction } from '@/composables/useAction'
import PageHeader from '@/components/PageHeader.vue'
import ListShell from '@/components/ListShell.vue'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import IdpForm from './IdpForm.vue'
import { POLICY_LABELS } from './idpForm'

const router = useRouter()
const { isGlobalAdmin } = storeToRefs(useAuthStore())
const list = usePagedList<IdentityProvider>(identityProviders.list)

const creating = ref(false)
const { busy, error, run } = useAction()

function openCreate() {
  error.value = null
  creating.value = true
}

async function create(body: IdentityProviderInput) {
  const idp = await run(() => identityProviders.create(body))
  if (idp) await router.push({ name: 'admin-identity-provider', params: { id: idp.id } })
}
</script>

<template>
  <section>
    <PageHeader
      title="Identity providers"
      description="External OpenID Connect providers your users can sign in with."
    >
      <template
        v-if="isGlobalAdmin"
        #actions
      >
        <button
          type="button"
          class="btn btn-primary"
          @click="openCreate"
        >
          New identity provider
        </button>
      </template>
    </PageHeader>
    <ListShell
      :list="list"
      empty="No identity providers yet."
    >
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              Name
            </th>
            <th
              scope="col"
              class="hidden md:table-cell"
            >
              Issuer
            </th>
            <th scope="col">
              Policy
            </th>
            <th scope="col">
              Status
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="idp in list.items"
            :key="idp.id"
          >
            <td>
              <RouterLink
                :to="{ name: 'admin-identity-provider', params: { id: idp.id } }"
                class="btn-link"
              >
                {{ idp.name }}
              </RouterLink>
            </td>
            <td class="mono muted hidden break-all md:table-cell">
              {{ idp.issuer }}
            </td>
            <td>{{ POLICY_LABELS[idp.policy] }}</td>
            <td class="space-x-1">
              <span class="badge">{{ idp.enabled ? 'Enabled' : 'Disabled' }}</span>
              <span
                v-if="!idp.visible"
                class="badge"
              >Hidden</span>
            </td>
          </tr>
        </tbody>
      </table>
    </ListShell>
    <ModalDialog
      :open="creating"
      title="New identity provider"
      wide
      @close="creating = false"
    >
      <IdpForm
        form-id="create-idp"
        @submit="create"
      />
      <ErrorAlert
        class="mt-4"
        :error="error"
      />
      <template #actions>
        <button
          type="button"
          class="btn"
          @click="creating = false"
        >
          Cancel
        </button>
        <button
          type="submit"
          form="create-idp"
          class="btn btn-primary"
          :disabled="busy"
        >
          Create
        </button>
      </template>
    </ModalDialog>
  </section>
</template>
