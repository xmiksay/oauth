<script setup lang="ts">
import { ref } from 'vue'
import { identityProviders } from '@/api/identityProviders'
import type { IdpGroupMapping } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { usePagedList } from '@/composables/usePagedList'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import ListShell from '@/components/ListShell.vue'
import PrincipalPicker, { type Picked } from '@/components/PrincipalPicker.vue'

/** Upstream claim value → local group mappings of one identity provider. */
const props = defineProps<{ idpId: string; canWrite: boolean }>()

const mappings = usePagedList<IdpGroupMapping>((q) => identityProviders.mappings(props.idpId, q))
const saver = useAction()
const claim = ref('groups')
const value = ref('')
const group = ref<Picked | null>(null)

async function add() {
  const picked = group.value
  if (!picked) return
  const body = { claim: claim.value.trim(), value: value.value, group_id: picked.id }
  if (await saver.run(() => identityProviders.addMapping(props.idpId, body))) {
    value.value = ''
    group.value = null
    await mappings.reload()
  }
}

function remove(id: string) {
  return identityProviders.removeMapping(props.idpId, id)
}
</script>

<template>
  <div class="card space-y-3">
    <h2 class="font-semibold">
      Group mappings
    </h2>
    <p class="muted text-sm">
      On every sign-in through this provider, a user whose ID token claim contains the value
      (exact match) is added to the group, and removed again once it doesn't. Memberships added
      by hand are never removed.
    </p>
    <form
      v-if="canWrite"
      class="grid gap-3 sm:grid-cols-2"
      data-testid="add-mapping"
      @submit.prevent="add"
    >
      <div>
        <label
          class="label"
          for="gm-claim"
        >Claim</label>
        <input
          id="gm-claim"
          v-model="claim"
          class="input"
          required
          maxlength="64"
          pattern="[A-Za-z0-9_.:/\-]+"
        >
      </div>
      <div>
        <label
          class="label"
          for="gm-value"
        >Value</label>
        <input
          id="gm-value"
          v-model="value"
          class="input"
          required
          maxlength="256"
        >
      </div>
      <div class="sm:col-span-2">
        <p
          v-if="group"
          class="mb-2 text-sm"
          data-testid="picked-group"
        >
          Group: <span class="font-medium">{{ group.label }}</span>
        </p>
        <PrincipalPicker
          kind="group"
          label="Group"
          @select="group = $event"
        />
      </div>
      <div class="sm:col-span-2">
        <button
          type="submit"
          class="btn btn-primary"
          :disabled="saver.busy.value || !group"
        >
          Add mapping
        </button>
      </div>
    </form>
    <ErrorAlert :error="saver.error.value" />
    <ListShell
      :list="mappings"
      empty="No group mappings."
    >
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              Claim
            </th>
            <th scope="col">
              Value
            </th>
            <th scope="col">
              Group
            </th>
            <th scope="col">
              <span class="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="m in mappings.items"
            :key="m.id"
          >
            <td class="mono">
              {{ m.claim }}
            </td>
            <td class="mono break-all">
              {{ m.value }}
            </td>
            <td>
              <RouterLink
                :to="{ name: 'admin-group', params: { id: m.group_id } }"
                class="btn-link"
              >
                {{ m.group_display_name ?? m.group_id }}
              </RouterLink>
            </td>
            <td class="text-right">
              <ConfirmButton
                v-if="canWrite"
                label="Remove"
                title="Remove mapping?"
                :message="`Members this mapping added to ${m.group_display_name ?? 'the group'} are removed, unless another mapping of this provider grants the group.`"
                danger
                :action="() => remove(m.id)"
                @done="mappings.reload()"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </ListShell>
  </div>
</template>
