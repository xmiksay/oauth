<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'
import { useAuthStore } from '@/stores/auth'
import { settings } from '@/api/access'
import { ROLE_LABELS, type Tenant } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import PageHeader from '@/components/PageHeader.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import { adminNav } from './nav'

const { slug } = storeToRefs(useTenantStore())
const { me, roles } = storeToRefs(useAuthStore())
const tenant = ref<Tenant | null>(null)
const { error, run } = useAction()

onMounted(async () => {
  tenant.value = (await run(settings.get)) ?? null
})
</script>

<template>
  <section>
    <PageHeader
      title="Overview"
      :description="tenant ? tenant.display_name : undefined"
    />
    <ErrorAlert :error="error" />
    <div class="grid gap-4 lg:grid-cols-2">
      <div class="card">
        <h2 class="font-semibold">
          Directory
        </h2>
        <dl
          v-if="tenant"
          class="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm"
        >
          <dt class="muted">
            Name
          </dt>
          <dd>{{ tenant.display_name }}</dd>
          <dt class="muted">
            Slug
          </dt>
          <dd class="mono">
            {{ tenant.slug }}
          </dd>
          <dt class="muted">
            Tenant ID
          </dt>
          <dd class="mono">
            {{ tenant.id }}
          </dd>
          <dt class="muted">
            Audit retention
          </dt>
          <dd>{{ tenant.audit_retention_days }} days</dd>
          <dt class="muted">
            Created
          </dt>
          <dd>{{ formatDate(tenant.created_at) }}</dd>
        </dl>
      </div>
      <div class="card">
        <h2 class="font-semibold">
          Signed in as
        </h2>
        <p class="mt-3 text-sm">
          {{ me?.display_name }} <span class="muted">({{ me?.email }})</span>
        </p>
        <p class="mt-2 flex flex-wrap gap-1">
          <span
            v-for="r in roles"
            :key="r"
            class="badge"
          >{{ ROLE_LABELS[r] }}</span>
        </p>
      </div>
    </div>
    <nav
      aria-label="Shortcuts"
      class="mt-6 grid gap-2 sm:grid-cols-2 lg:grid-cols-4"
    >
      <RouterLink
        v-for="item in adminNav.filter((i) => !i.systemOnly)"
        :key="item.name"
        :to="{ name: item.name, params: { tenant: slug } }"
        class="card text-sm font-medium hover:border-blue-600 sm:p-4"
      >
        {{ item.label }}
      </RouterLink>
    </nav>
  </section>
</template>
