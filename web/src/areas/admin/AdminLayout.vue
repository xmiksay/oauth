<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'
import { useAuthStore } from '@/stores/auth'
import AppHeader from '@/components/AppHeader.vue'
import SignedInGate from '@/components/SignedInGate.vue'
import { adminNav, SYSTEM_TENANT } from './nav'

const { slug } = storeToRefs(useTenantStore())
const auth = useAuthStore()
const { isAdmin, isGlobalAdmin } = storeToRefs(auth)
const route = useRoute()
const menuOpen = ref(false)

const nav = computed(() =>
  adminNav.filter((i) => !i.systemOnly || (slug.value === SYSTEM_TENANT && isGlobalAdmin.value)),
)

watch(() => route.fullPath, () => (menuOpen.value = false))

function closeOnEscape(e: KeyboardEvent) {
  if (e.key === 'Escape') menuOpen.value = false
}
onMounted(() => window.addEventListener('keydown', closeOnEscape))
onUnmounted(() => window.removeEventListener('keydown', closeOnEscape))
</script>

<template>
  <div class="flex min-h-screen flex-col">
    <AppHeader
      title="Admin center"
      :tenant="slug"
      menu-button
      :menu-open="menuOpen"
      @toggle-menu="menuOpen = !menuOpen"
    />
    <SignedInGate>
      <div
        v-if="!isAdmin"
        class="mx-auto max-w-xl p-6"
      >
        <h1 class="text-xl font-semibold">
          You don't have access to the admin center
        </h1>
        <p class="muted mt-2 text-sm">
          The admin center needs a directory role (Global Administrator, User Administrator or
          Application Administrator). Ask an administrator of this directory to assign you one.
        </p>
        <RouterLink
          :to="{ name: 'myaccount' }"
          class="btn mt-4"
        >
          Go to My Account
        </RouterLink>
      </div>
      <div
        v-else
        class="flex flex-1"
      >
        <div
          v-if="menuOpen"
          class="fixed inset-0 top-12 z-(--z-backdrop) bg-black/30 md:hidden"
          aria-hidden="true"
          @click="menuOpen = false"
        />
        <nav
          id="side-nav"
          aria-label="Admin sections"
          class="fixed top-12 bottom-0 left-0 z-(--z-sidenav) w-56 shrink-0 overflow-y-auto border-r border-neutral-200 bg-white p-2 md:static md:block dark:border-neutral-800 dark:bg-neutral-900"
          :class="menuOpen ? 'block' : 'hidden'"
        >
          <ul class="space-y-1">
            <li>
              <RouterLink
                :to="{ name: 'admin' }"
                class="nav-link"
                exact-active-class="nav-link-active"
              >
                Overview
              </RouterLink>
            </li>
            <li
              v-for="item in nav"
              :key="item.name"
            >
              <RouterLink
                :to="{ name: item.name }"
                class="nav-link"
                active-class="nav-link-active"
              >
                {{ item.label }}
              </RouterLink>
            </li>
          </ul>
        </nav>
        <main class="min-w-0 flex-1 p-4 sm:p-6">
          <!-- Keyed by :id so users/A → users/B remounts the detail page (lists key to ''). -->
          <RouterView v-slot="{ Component, route: r }">
            <component
              :is="Component"
              :key="String(r.params.id ?? '')"
            />
          </RouterView>
        </main>
      </div>
    </SignedInGate>
  </div>
</template>

<style scoped>
@reference 'tailwindcss';

.nav-link {
  @apply block rounded px-3 py-2 text-sm text-neutral-700 hover:bg-neutral-100 focus-visible:outline-2 focus-visible:outline-blue-600 dark:text-neutral-300 dark:hover:bg-neutral-800;
}
.nav-link-active {
  @apply bg-neutral-100 font-medium text-neutral-900 dark:bg-neutral-800 dark:text-neutral-100;
}
</style>
