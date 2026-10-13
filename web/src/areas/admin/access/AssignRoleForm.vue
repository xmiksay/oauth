<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { roleAssignments } from '@/api/access'
import type { AppRole, PrincipalType } from '@/api/types'
import { useAction } from '@/composables/useAction'
import ErrorAlert from '@/components/ErrorAlert.vue'
import PrincipalPicker, { type Picked } from '@/components/PrincipalPicker.vue'

const props = defineProps<{ roles: AppRole[] }>()
const emit = defineEmits<{ assigned: [] }>()

const kind = ref<PrincipalType>('user')
const principal = ref<Picked | null>(null)
const roleId = ref('')
const { busy, error, run } = useAction()

/** Users and groups take roles allowing `user`; client apps those allowing `application`. */
const allowed = computed(() =>
  props.roles.filter((r) =>
    r.allowed_member_types.includes(kind.value === 'application' ? 'application' : 'user'),
  ),
)

watch(
  allowed,
  (roles) => {
    if (!roles.some((r) => r.id === roleId.value)) roleId.value = roles[0]?.id ?? ''
  },
  { immediate: true },
)
watch(kind, () => (principal.value = null))

async function assign() {
  const p = principal.value
  if (!p || !roleId.value) return
  const ok = await run(() =>
    roleAssignments.create({
      app_role_id: roleId.value,
      principal_type: kind.value,
      principal_id: p.id,
    }),
  )
  if (!ok) return
  principal.value = null
  emit('assigned')
}
</script>

<template>
  <form
    class="card grid gap-3 md:grid-cols-[auto_2fr_1fr_auto] md:items-end"
    @submit.prevent="assign"
  >
    <div>
      <label
        class="label"
        for="ra-kind"
      >Assign to</label>
      <select
        id="ra-kind"
        v-model="kind"
        class="input"
      >
        <option value="user">
          User
        </option>
        <option value="group">
          Group
        </option>
        <option value="application">
          Application
        </option>
      </select>
    </div>
    <div>
      <PrincipalPicker
        v-if="!principal"
        :kind="kind"
        :label="kind === 'application' ? 'Client application' : `Pick a ${kind}`"
        @select="principal = $event"
      />
      <p
        v-else
        class="text-sm"
      >
        <span class="label">Selected</span>
        {{ principal.label }}
        <button
          type="button"
          class="btn-link ml-1"
          @click="principal = null"
        >
          Change
        </button>
      </p>
    </div>
    <div>
      <label
        class="label"
        for="ra-role"
      >Role</label>
      <select
        id="ra-role"
        v-model="roleId"
        class="input"
        :disabled="!allowed.length"
      >
        <option
          v-for="r in allowed"
          :key="r.id"
          :value="r.id"
        >
          {{ r.display_name || r.value }}
        </option>
      </select>
    </div>
    <button
      type="submit"
      class="btn btn-primary"
      :disabled="busy || !principal || !roleId"
    >
      Assign
    </button>
    <p
      v-if="!allowed.length"
      class="muted text-sm md:col-span-4"
    >
      No role of this app can be assigned to a {{ kind }}.
    </p>
    <ErrorAlert
      class="md:col-span-4"
      :error="error"
    />
  </form>
</template>
