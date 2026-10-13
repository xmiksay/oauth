<script setup lang="ts">
import { ref, watch } from 'vue'
import { scopes as scopesApi } from '@/api/applications'
import type { Scope } from '@/api/types'
import { useAction } from '@/composables/useAction'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'

/** Edits a scope's consent description and who may consent (the value is immutable). */
const props = defineProps<{ appId: string; scope: Scope | null }>()
const emit = defineEmits<{ close: []; saved: [] }>()

const description = ref('')
const adminOnly = ref(false)
const { busy, error, run } = useAction()

watch(
  () => props.scope,
  (s) => {
    description.value = s?.description ?? ''
    adminOnly.value = s?.admin_consent_required ?? false
    error.value = null
  },
)

async function save() {
  const s = props.scope
  if (!s || busy.value) return
  const body: { description?: string; admin_consent_required?: boolean } = {}
  if (description.value.trim() !== s.description) body.description = description.value.trim()
  if (adminOnly.value !== s.admin_consent_required) body.admin_consent_required = adminOnly.value
  const ok = await run(() => scopesApi.update(props.appId, s.id, body))
  if (ok) emit('saved')
}
</script>

<template>
  <ModalDialog
    :open="scope !== null"
    :title="`Edit scope ${scope?.value ?? ''}`"
    @close="busy || emit('close')"
  >
    <form
      id="edit-scope"
      class="space-y-4"
      @submit.prevent="save"
    >
      <div>
        <label
          class="label"
          for="es-desc"
        >Description shown on consent</label>
        <input
          id="es-desc"
          v-model="description"
          class="input"
        >
      </div>
      <label class="flex items-center gap-2 text-sm">
        <input
          v-model="adminOnly"
          type="checkbox"
        >
        Admin consent only
      </label>
      <ErrorAlert :error="error" />
    </form>
    <template #actions>
      <button
        type="button"
        class="btn"
        :disabled="busy"
        @click="emit('close')"
      >
        Cancel
      </button>
      <button
        type="submit"
        form="edit-scope"
        class="btn btn-primary"
        :disabled="busy"
      >
        Save
      </button>
    </template>
  </ModalDialog>
</template>
