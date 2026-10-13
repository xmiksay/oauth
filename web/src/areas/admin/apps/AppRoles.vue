<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useApplicationStore } from '@/stores/application'
import { appRoles } from '@/api/applications'
import type { AppRole, MemberType } from '@/api/types'
import { useAction } from '@/composables/useAction'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import ModalDialog from '@/components/ModalDialog.vue'

const { app, canEditConfig } = storeToRefs(useApplicationStore())
const items = ref<AppRole[]>([])
const loader = useAction()
const saver = useAction()

/** `null` = closed; `editing` = the role being edited (create otherwise). */
const form = ref<{
  editing: AppRole | null
  value: string
  display_name: string
  description: string
  types: MemberType[]
} | null>(null)

async function load() {
  if (!app.value) return
  const id = app.value.id
  const res = await loader.run(() => appRoles.list(id))
  if (res) items.value = res.items
}

onMounted(load)

function openCreate() {
  saver.error.value = null
  form.value = { editing: null, value: '', display_name: '', description: '', types: ['user'] }
}

function openEdit(r: AppRole) {
  saver.error.value = null
  form.value = {
    editing: r,
    value: r.value,
    display_name: r.display_name,
    description: r.description,
    types: [...r.allowed_member_types],
  }
}

async function save() {
  const f = form.value
  if (!f || !app.value) return
  const id = app.value.id
  const body = {
    display_name: f.display_name.trim(),
    description: f.description.trim(),
    allowed_member_types: f.types,
  }
  const editing = f.editing
  const ok = await saver.run(() =>
    editing
      ? appRoles.update(id, editing.id, body)
      : appRoles.create(id, { ...body, value: f.value.trim() }),
  )
  if (!ok) return
  form.value = null
  await load()
}

async function remove(roleId: string) {
  if (app.value) await appRoles.remove(app.value.id, roleId)
}
</script>

<template>
  <div
    v-if="app"
    class="space-y-4"
  >
    <div class="flex flex-wrap items-center justify-between gap-2">
      <p class="muted text-sm">
        App roles are assigned to users, groups or applications and appear in the
        <span class="mono">roles</span> claim of tokens for this app.
      </p>
      <button
        v-if="canEditConfig"
        type="button"
        class="btn btn-primary"
        @click="openCreate"
      >
        New app role
      </button>
    </div>
    <ErrorAlert :error="loader.error.value" />
    <div class="card overflow-x-auto p-0 sm:p-0">
      <table
        v-if="items.length"
        class="table"
      >
        <thead>
          <tr>
            <th scope="col">
              Display name
            </th>
            <th scope="col">
              Value
            </th>
            <th scope="col">
              Allowed members
            </th>
            <th scope="col">
              <span class="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="r in items"
            :key="r.id"
          >
            <td>
              {{ r.display_name }}
              <span class="muted block text-xs">{{ r.description }}</span>
            </td>
            <td class="mono">
              {{ r.value }}
            </td>
            <td>{{ r.allowed_member_types.join(', ') }}</td>
            <td class="space-x-1 text-right whitespace-nowrap">
              <template v-if="canEditConfig">
                <button
                  type="button"
                  class="btn"
                  @click="openEdit(r)"
                >
                  Edit
                </button>
                <ConfirmButton
                  label="Delete"
                  title="Delete app role?"
                  :message="`${r.value} and all its assignments are deleted.`"
                  danger
                  :action="() => remove(r.id)"
                  @done="load"
                />
              </template>
            </td>
          </tr>
        </tbody>
      </table>
      <p
        v-else
        class="muted p-4 text-sm"
      >
        No app roles.
      </p>
    </div>
    <ModalDialog
      :open="form !== null"
      :title="form?.editing ? 'Edit app role' : 'New app role'"
      @close="form = null"
    >
      <form
        v-if="form"
        id="role-form"
        class="space-y-4"
        @submit.prevent="save"
      >
        <div>
          <label
            class="label"
            for="ar-name"
          >Display name</label>
          <input
            id="ar-name"
            v-model="form.display_name"
            class="input"
            required
          >
        </div>
        <div>
          <label
            class="label"
            for="ar-value"
          >Value</label>
          <input
            id="ar-value"
            v-model="form.value"
            class="input font-mono"
            :disabled="!!form.editing"
            placeholder="Orders.Admin"
            required
          >
          <p class="hint">
            Appears in the roles claim. Can't be changed later.
          </p>
        </div>
        <div>
          <label
            class="label"
            for="ar-desc"
          >Description</label>
          <input
            id="ar-desc"
            v-model="form.description"
            class="input"
          >
        </div>
        <fieldset>
          <legend class="label">
            Allowed member types
          </legend>
          <label class="flex items-center gap-2 text-sm">
            <input
              v-model="form.types"
              type="checkbox"
              value="user"
            >
            Users / groups
          </label>
          <label class="mt-1 flex items-center gap-2 text-sm">
            <input
              v-model="form.types"
              type="checkbox"
              value="application"
            >
            Applications
          </label>
        </fieldset>
        <ErrorAlert :error="saver.error.value" />
      </form>
      <template #actions>
        <button
          type="button"
          class="btn"
          @click="form = null"
        >
          Cancel
        </button>
        <button
          type="submit"
          form="role-form"
          class="btn btn-primary"
          :disabled="saver.busy.value || !form?.types.length"
        >
          Save
        </button>
      </template>
    </ModalDialog>
  </div>
</template>
