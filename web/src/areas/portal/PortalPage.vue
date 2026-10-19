<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'
import { useAuthStore } from '@/stores/auth'
import AppHeader from '@/components/AppHeader.vue'
import SignedInGate from '@/components/SignedInGate.vue'

/** The tenant root: signed in through the My Account client, links into each app. */
const { slug } = storeToRefs(useTenantStore())
const { me, isAdmin } = storeToRefs(useAuthStore())

const quickLinks = [
  { name: 'myaccount-security', label: 'Security info' },
  { name: 'myaccount-sessions', label: 'Devices & sessions' },
  { name: 'myaccount-apps', label: 'App permissions' },
]
</script>

<template>
  <div class="flex min-h-screen flex-col">
    <AppHeader
      title="Dashboard"
      :tenant="slug"
    />
    <SignedInGate>
      <main class="mx-auto w-full max-w-4xl p-4 sm:p-6">
        <h1 class="text-2xl font-semibold">
          Hello, {{ me?.display_name || me?.email }}
        </h1>
        <p class="muted mt-1 text-sm">
          {{ me?.email }}
        </p>
        <div class="mt-6 grid gap-4 sm:grid-cols-2">
          <RouterLink
            :to="{ name: 'myaccount' }"
            class="card block hover:border-blue-600 focus-visible:outline-2 focus-visible:outline-blue-600"
          >
            <h2 class="font-semibold">
              My Account
            </h2>
            <p class="muted mt-1 text-sm">
              Your profile, password, sign-in methods, devices and app permissions.
            </p>
          </RouterLink>
          <RouterLink
            v-if="isAdmin"
            :to="{ name: 'admin' }"
            class="card block hover:border-blue-600 focus-visible:outline-2 focus-visible:outline-blue-600"
          >
            <h2 class="font-semibold">
              Admin center
            </h2>
            <p class="muted mt-1 text-sm">
              Manage users, groups, app registrations and access for {{ slug }}.
            </p>
          </RouterLink>
        </div>
        <h2 class="mt-8 font-semibold">
          Quick links
        </h2>
        <ul class="mt-2 space-y-1">
          <li
            v-for="link in quickLinks"
            :key="link.name"
          >
            <RouterLink
              :to="{ name: link.name }"
              class="btn-link"
            >
              {{ link.label }}
            </RouterLink>
          </li>
        </ul>
      </main>
    </SignedInGate>
  </div>
</template>
