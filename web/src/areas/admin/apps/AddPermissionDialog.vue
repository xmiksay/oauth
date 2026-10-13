<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { appRoles, requiredPermissions, scopes } from '@/api/applications'
import type { AppRole, PermissionType, Scope } from '@/api/types'
import { useAction } from '@/composables/useAction'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import PrincipalPicker, { type Picked } from '@/components/PrincipalPicker.vue'

const props = defineProps<{ open: boolean; appId: string }>()
/** `changed`: some permissions were added before a later one failed — the parent reloads. */
const emit = defineEmits<{ close: []; added: []; changed: [] }>()

const resource = ref<Picked | null>(null)
const type = ref<PermissionType>('delegated')
const exposed = ref<{ scopes: Scope[]; roles: AppRole[] }>({ scopes: [], roles: [] })
const chosen = ref<string[]>([])
const { busy, error, run } = useAction()

watch(
  () => props.open,
  (open) => {
    if (!open) return
    resource.value = null
    chosen.value = []
    error.value = null
  },
)

async function pickResource(p: Picked) {
  resource.value = p
  chosen.value = []
  exposed.value = { scopes: [], roles: [] }
  const res = await run(async () => {
    const [s, r] = await Promise.all([scopes.list(p.id), appRoles.list(p.id)])
    return {
      scopes: s.items,
      roles: r.items.filter((role) => role.allowed_member_types.includes('application')),
    }
  })
  if (res) exposed.value = res
}

const options = computed(() =>
  type.value === 'delegated'
    ? exposed.value.scopes.map((s) => ({ value: s.value, text: s.description }))
    : exposed.value.roles.map((r) => ({ value: r.value, text: r.display_name })),
)

watch(type, () => (chosen.value = []))

async function add() {
  const res = resource.value
  if (!res) return
  let added = 0
  const ok = await run(async () => {
    for (const value of chosen.value) {
      await requiredPermissions.create(props.appId, {
        resource_application_id: res.id,
        type: type.value,
        value,
      })
      added++
    }
    return true
  })
  if (ok) emit('added')
  else if (added > 0) emit('changed')
}
</script>

<template>
  <ModalDialog
    :open="open"
    title="Request API permissions"
    wide
    @close="emit('close')"
  >
    <div class="space-y-4">
      <PrincipalPicker
        v-if="!resource"
        kind="application"
        label="API (resource application)"
        @select="pickResource"
      />
      <template v-else>
        <p class="text-sm">
          <strong>{{ resource.label }}</strong> <span class="mono muted">{{ resource.detail }}</span>
          <button
            type="button"
            class="btn-link ml-2"
            @click="resource = null"
          >
            Change
          </button>
        </p>
        <fieldset class="flex flex-wrap gap-4 text-sm">
          <legend class="label">
            Type
          </legend>
          <label class="flex items-center gap-2"><input
            v-model="type"
            type="radio"
            value="delegated"
          > Delegated (as the signed-in user)</label>
          <label class="flex items-center gap-2"><input
            v-model="type"
            type="radio"
            value="application"
          > Application (app-only)</label>
        </fieldset>
        <fieldset>
          <legend class="label">
            Permissions
          </legend>
          <p
            v-if="!options.length"
            class="muted text-sm"
          >
            This API exposes no {{ type === 'delegated' ? 'scopes' : 'app roles for applications' }}.
          </p>
          <label
            v-for="o in options"
            :key="o.value"
            class="flex items-start gap-2 py-1 text-sm"
          >
            <input
              v-model="chosen"
              type="checkbox"
              :value="o.value"
              class="mt-1"
            >
            <span><span class="mono">{{ o.value }}</span> <span class="muted">{{ o.text }}</span></span>
          </label>
        </fieldset>
      </template>
      <ErrorAlert :error="error" />
    </div>
    <template #actions>
      <button
        type="button"
        class="btn"
        @click="emit('close')"
      >
        Cancel
      </button>
      <button
        type="button"
        class="btn btn-primary"
        :disabled="busy || !chosen.length"
        @click="add"
      >
        Add permissions
      </button>
    </template>
  </ModalDialog>
</template>
