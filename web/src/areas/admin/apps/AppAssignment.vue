<script setup lang="ts">
import { ref, watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useApplicationStore } from '@/stores/application'
import { useAction } from '@/composables/useAction'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'

/** The "assignment required" switch (docs/api/management.md); built-in apps can't use it. */
const store = useApplicationStore()
const { app, canEditConfig } = storeToRefs(store)
const required = ref(false)
const saved = ref(false)
const { busy, error, run } = useAction()

watchEffect(() => {
  required.value = app.value?.assignment_required ?? false
})

async function save() {
  saved.value = false
  const ok = await run(() => store.update({ assignment_required: required.value }))
  saved.value = !!ok
}
</script>

<template>
  <form
    v-if="app"
    class="card space-y-3"
    @submit.prevent="save"
    @input="saved = false"
  >
    <label class="flex items-center gap-2 text-sm font-medium">
      <input
        id="as-required"
        v-model="required"
        type="checkbox"
        :disabled="!canEditConfig"
        aria-describedby="as-required-hint"
      >
      Assignment required
    </label>
    <p
      id="as-required-hint"
      class="hint"
    >
      Only users holding one of this app's roles (directly or through a group) can sign in to it
      or get tokens for it, and only applications granted one of its application permissions get
      app-only tokens for it. Removing an assignment stops new tokens; issued access tokens stay
      valid until they expire.
    </p>
    <ErrorAlert :error="error" />
    <StatusNote :message="saved ? 'Saved.' : null" />
    <button
      v-if="canEditConfig"
      type="submit"
      class="btn btn-primary"
      :disabled="busy || required === app.assignment_required"
    >
      Save
    </button>
  </form>
</template>
