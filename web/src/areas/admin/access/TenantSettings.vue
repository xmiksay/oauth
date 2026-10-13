<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { settings } from '@/api/access'
import type { Tenant } from '@/api/types'
import { useAction } from '@/composables/useAction'
import PageHeader from '@/components/PageHeader.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'

const { isGlobalAdmin } = storeToRefs(useAuthStore())
const tenant = ref<Tenant | null>(null)
const name = ref('')
const retention = ref(90)
const saved = ref(false)
const loader = useAction()
const saver = useAction()

function fill(t: Tenant) {
  tenant.value = t
  name.value = t.display_name
  retention.value = t.audit_retention_days
}

onMounted(async () => {
  const t = await loader.run(settings.get)
  if (t) fill(t)
})

async function save() {
  const t = tenant.value
  if (!t) return
  saved.value = false
  const body: { display_name?: string; audit_retention_days?: number } = {}
  if (name.value.trim() !== t.display_name) body.display_name = name.value.trim()
  if (retention.value !== t.audit_retention_days) body.audit_retention_days = retention.value
  const updated = await saver.run(() => settings.update(body))
  if (updated) {
    fill(updated)
    saved.value = true
  }
}
</script>

<template>
  <section>
    <PageHeader
      title="Settings"
      description="Directory-wide settings. Only Global Administrators can change them."
    />
    <ErrorAlert :error="loader.error.value" />
    <form
      v-if="tenant"
      class="card max-w-xl space-y-4"
      @submit.prevent="save"
      @input="saved = false"
    >
      <div>
        <label
          class="label"
          for="ts-name"
        >Directory name</label>
        <input
          id="ts-name"
          v-model="name"
          class="input"
          :disabled="!isGlobalAdmin"
          required
        >
        <p class="hint">
          Shown on the sign-in page and as the issuer name in authenticator apps.
        </p>
      </div>
      <div>
        <label
          class="label"
          for="ts-retention"
        >Audit log retention (days)</label>
        <input
          id="ts-retention"
          v-model.number="retention"
          class="input"
          type="number"
          min="30"
          max="3650"
          :disabled="!isGlobalAdmin"
          required
        >
        <p class="hint">
          30–3650 days.
        </p>
      </div>
      <p class="mono muted">
        Tenant ID {{ tenant.id }} · slug {{ tenant.slug }}
      </p>
      <ErrorAlert :error="saver.error.value" />
      <StatusNote :message="saved ? 'Saved.' : null" />
      <button
        v-if="isGlobalAdmin"
        type="submit"
        class="btn btn-primary"
        :disabled="saver.busy.value"
      >
        Save
      </button>
    </form>
  </section>
</template>
