<script setup lang="ts">
import { ref, watch } from 'vue'
import { tenants } from '@/api/access'
import type { Tenant } from '@/api/types'
import { useAction } from '@/composables/useAction'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'

/** A system Global Admin renames a tenant or changes its audit retention. */
const props = defineProps<{ tenant: Tenant | null }>()
const emit = defineEmits<{ close: []; saved: [] }>()

const name = ref('')
const retention = ref(90)
const { busy, error, run } = useAction()

watch(
  () => props.tenant,
  (t) => {
    name.value = t?.display_name ?? ''
    retention.value = t?.audit_retention_days ?? 90
    error.value = null
  },
)

async function save() {
  const t = props.tenant
  if (!t || busy.value) return
  const body: { display_name?: string; audit_retention_days?: number } = {}
  if (name.value.trim() !== t.display_name) body.display_name = name.value.trim()
  if (retention.value !== t.audit_retention_days) body.audit_retention_days = retention.value
  if (await run(() => tenants.update(t.slug, body))) emit('saved')
}
</script>

<template>
  <ModalDialog
    :open="tenant !== null"
    :title="`Edit tenant ${tenant?.slug ?? ''}`"
    @close="busy || emit('close')"
  >
    <form
      id="edit-tenant"
      class="space-y-4"
      @submit.prevent="save"
    >
      <div>
        <label
          class="label"
          for="et-name"
        >Display name</label>
        <input
          id="et-name"
          v-model="name"
          class="input"
          required
        >
      </div>
      <div>
        <label
          class="label"
          for="et-retention"
        >Audit log retention (days)</label>
        <input
          id="et-retention"
          v-model.number="retention"
          class="input"
          type="number"
          min="30"
          max="3650"
          required
        >
        <p class="hint">
          30–3650 days.
        </p>
      </div>
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
        form="edit-tenant"
        class="btn btn-primary"
        :disabled="busy"
      >
        Save
      </button>
    </template>
  </ModalDialog>
</template>
