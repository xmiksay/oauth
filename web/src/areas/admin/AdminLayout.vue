<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useTenantStore } from '@/stores/tenant'
import { useAuthStore } from '@/stores/auth'
import AppHeader from '@/components/AppHeader.vue'
import SignedInGate from '@/components/SignedInGate.vue'
import { adminPageKey } from '@/router/admin'
import { adminNav, SYSTEM_TENANT } from './nav'

const { slug } = storeToRefs(useTenantStore())
const auth = useAuthStore()
const { isAdmin, isGlobalAdmin } = storeToRefs(auth)
const route = useRoute()
const menuOpen = ref(false)
const header = ref<InstanceType<typeof AppHeader> | null>(null)
const sideNav = ref<HTMLElement | null>(null)
const mainEl = ref<HTMLElement | null>(null)

const nav = computed(() =>
  adminNav.filter((i) => !i.systemOnly || (slug.value === SYSTEM_TENANT && isGlobalAdmin.value)),
)

// A nav link hides the overlay it sits in, which would drop focus to body: land on the page.
watch(
  () => route.fullPath,
  async () => {
    if (!menuOpen.value) return
    menuOpen.value = false
    await nextTick()
    mainEl.value?.focus()
  },
)

// Into the nav on open: its Escape and focus-leave handling only work with focus inside it.
watch(menuOpen, async (open) => {
  if (!open) return
  await nextTick()
  sideNav.value?.querySelector<HTMLElement>('a')?.focus()
})

// Focus leaving the overlay closes it, so it never hides what has focus. Not on the way to the
// toggle (its click closes it), nor to nowhere (null: a click on the nav's own background).
function closeOnFocusLeave(e: FocusEvent) {
  const next = e.relatedTarget as Node | null
  if (!menuOpen.value || !next || sideNav.value?.contains(next)) return
  if (header.value?.isMenuButton(next)) return
  menuOpen.value = false
}

// The one Escape path: on window, so focus fallen to body (a tap on the nav's background) still
// closes it, and after document's listeners, so an Escape the open app launcher took (prevented)
// isn't ours too. Escapes from the main content, the rest of the header or a dialog never
// touch it.
function closeOnEscape(e: KeyboardEvent) {
  if (e.key !== 'Escape' || e.defaultPrevented || !menuOpen.value) return
  if (e.target instanceof Element && e.target.closest('dialog')) return
  const active = document.activeElement
  const ours = !active || active === document.body || sideNav.value?.contains(active) || header.value?.isMenuButton(active)
  if (!ours) return
  e.preventDefault()
  menuOpen.value = false
  header.value?.focusMenuButton()
}
watch(menuOpen, (open) => {
  if (open) window.addEventListener('keydown', closeOnEscape)
  else window.removeEventListener('keydown', closeOnEscape)
})

// From md up the nav is static and `menuOpen` invisible: reset it, or the overlay reappears
// on the way back down.
let wide: MediaQueryList | null = null
const resetMenu = () => (menuOpen.value = false)
onMounted(() => {
  wide = window.matchMedia('(min-width: 48rem)')
  wide.addEventListener('change', resetMenu)
})
onUnmounted(() => {
  wide?.removeEventListener('change', resetMenu)
  window.removeEventListener('keydown', closeOnEscape)
})
</script>

<template>
  <div class="flex min-h-screen flex-col">
    <AppHeader
      ref="header"
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
          class="fixed inset-0 top-header z-backdrop bg-black/30 md:hidden"
          aria-hidden="true"
          @click="menuOpen = false"
        />
        <nav
          id="side-nav"
          ref="sideNav"
          aria-label="Admin sections"
          class="fixed top-header bottom-0 left-0 z-sidenav w-56 shrink-0 overflow-y-auto border-r border-neutral-200 bg-white p-2 md:static md:block dark:border-neutral-800 dark:bg-neutral-900"
          :class="menuOpen ? 'block' : 'hidden'"
          @focusout="closeOnFocusLeave"
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
        <main
          ref="mainEl"
          tabindex="-1"
          class="min-w-0 flex-1 p-4 outline-none sm:p-6"
        >
          <!-- Keyed by the route's object (:id / :slug) so users/A → users/B remounts the page. -->
          <RouterView v-slot="{ Component, route: r }">
            <component
              :is="Component"
              :key="adminPageKey(r)"
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
