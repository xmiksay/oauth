<script setup lang="ts">
import { ref } from 'vue'
import { tenants } from '@/api/access'
import type { Tenant } from '@/api/types'
import { usePagedList } from '@/composables/usePagedList'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import PageHeader from '@/components/PageHeader.vue'
import ListShell from '@/components/ListShell.vue'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import SecretOnceDialog from '@/components/SecretOnceDialog.vue'
import { tenantOrigin } from '@/stores/tenant'
import EditTenantDialog from './EditTenantDialog.vue'

const list = usePagedList<Tenant>(tenants.list)
const creating = ref(false)
const form = ref({ slug: '', display_name: '', admin_email: '', admin_display_name: '' })
const oneTime = ref<string[] | null>(null)
const createdFor = ref('')
const editing = ref<Tenant | null>(null)
const { busy, error, run } = useAction()

function openCreate() {
  form.value = { slug: '', display_name: '', admin_email: '', admin_display_name: '' }
  error.value = null
  creating.value = true
}

async function create() {
  const f = form.value
  const res = await run(() =>
    tenants.create({
      slug: f.slug.trim(),
      display_name: f.display_name.trim(),
      admin_email: f.admin_email.trim(),
      ...(f.admin_display_name.trim() ? { admin_display_name: f.admin_display_name.trim() } : {}),
    }),
  )
  if (!res) return
  creating.value = false
  createdFor.value = `${res.admin.email} — sign in at ${tenantOrigin(res.tenant.slug)}/admin`
  oneTime.value = [res.one_time_password]
  await list.reload()
}

function setDisabled(t: Tenant) {
  return tenants.update(t.slug, { disabled: !t.disabled })
}
</script>

<template>
  <section>
    <PageHeader
      title="Tenants"
      description="Directories hosted by this service. Disabled tenants answer 404 everywhere."
    >
      <template #actions>
        <button
          type="button"
          class="btn btn-primary"
          @click="openCreate"
        >
          New tenant
        </button>
      </template>
    </PageHeader>
    <ListShell
      :list="list"
      search-label="Search by slug or name"
      empty="No tenants found."
    >
      <table class="table">
        <thead>
          <tr>
            <th scope="col">
              Name
            </th>
            <th scope="col">
              Slug
            </th>
            <th scope="col">
              Status
            </th>
            <th
              scope="col"
              class="hidden md:table-cell"
            >
              Created
            </th>
            <th scope="col">
              <span class="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="t in list.items"
            :key="t.id"
          >
            <td>
              {{ t.display_name }}
              <span
                v-if="t.is_system"
                class="badge ml-1"
              >System</span>
            </td>
            <td class="mono">
              {{ t.slug }}
            </td>
            <td>{{ t.disabled ? 'Disabled' : 'Active' }}</td>
            <td class="hidden md:table-cell">
              {{ formatDate(t.created_at) }}
            </td>
            <td class="space-x-1 text-right whitespace-nowrap">
              <button
                type="button"
                class="btn"
                @click="editing = t"
              >
                Edit
              </button>
              <ConfirmButton
                v-if="!t.is_system"
                :label="t.disabled ? 'Enable' : 'Disable'"
                :title="t.disabled ? 'Enable tenant?' : 'Disable tenant?'"
                :message="
                  t.disabled
                    ? `${t.slug} becomes reachable again.`
                    : `${t.slug} stops working: sign-in, tokens and the API answer 404.`
                "
                :danger="!t.disabled"
                :action="() => setDisabled(t)"
                @done="list.load()"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </ListShell>
    <ModalDialog
      :open="creating"
      title="New tenant"
      @close="creating = false"
    >
      <form
        id="create-tenant"
        class="space-y-4"
        @submit.prevent="create"
      >
        <div>
          <label
            class="label"
            for="nt-slug"
          >Slug</label>
          <input
            id="nt-slug"
            v-model="form.slug"
            class="input font-mono"
            pattern="[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]"
            required
          >
          <p class="hint">
            2–63 lowercase letters, digits and dashes (not at the end); the tenant's host is
            <span class="font-mono">{{ tenantOrigin(form.slug || 'slug') }}</span>.
          </p>
        </div>
        <div>
          <label
            class="label"
            for="nt-name"
          >Display name</label>
          <input
            id="nt-name"
            v-model="form.display_name"
            class="input"
            required
          >
        </div>
        <div>
          <label
            class="label"
            for="nt-email"
          >First administrator's email</label>
          <input
            id="nt-email"
            v-model="form.admin_email"
            class="input"
            type="email"
            required
          >
        </div>
        <div>
          <label
            class="label"
            for="nt-admin-name"
          >Administrator's display name (optional)</label>
          <input
            id="nt-admin-name"
            v-model="form.admin_display_name"
            class="input"
          >
        </div>
        <ErrorAlert :error="error" />
      </form>
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
          form="create-tenant"
          class="btn btn-primary"
          :disabled="busy"
        >
          Create
        </button>
      </template>
    </ModalDialog>
    <EditTenantDialog
      :tenant="editing"
      @close="editing = null"
      @saved="editing = null; list.load()"
    />
    <SecretOnceDialog
      title="Administrator's temporary password"
      :description="createdFor"
      :values="oneTime"
      @close="oneTime = null"
    />
  </section>
</template>
