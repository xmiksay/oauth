<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, type RouteLocationRaw } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'

/** Grid button switching between the portal, My Account and (with a directory role) the admin center. */
type AppId = 'portal' | 'myaccount' | 'admin'

const { isAdmin } = storeToRefs(useAuthStore())
const route = useRoute()
const open = ref(false)
const root = ref<HTMLElement | null>(null)
const toggle = ref<HTMLButtonElement | null>(null)

const current = computed<AppId>(() => {
  if (route.path.startsWith('/admin')) return 'admin'
  if (route.path.startsWith('/myaccount')) return 'myaccount'
  return 'portal'
})

const apps = computed(() => {
  const all: { id: AppId; label: string; to: RouteLocationRaw }[] = [
    { id: 'portal', label: 'Dashboard', to: { name: 'portal' } },
    { id: 'myaccount', label: 'My Account', to: { name: 'myaccount' } },
  ]
  if (isAdmin.value) all.push({ id: 'admin', label: 'Admin center', to: { name: 'admin' } })
  return all
})

watch(() => route.fullPath, () => (open.value = false))

async function onToggle() {
  open.value = !open.value
  if (open.value) {
    await nextTick()
    root.value?.querySelector<HTMLElement>('a')?.focus()
  }
}

function close(refocus: boolean) {
  if (!open.value) return
  open.value = false
  if (refocus) toggle.value?.focus()
}

// On document, not the root: focus may have left the menu (e.g. fallen to body) while it's open.
function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape') close(true)
}
watch(open, (isOpen) => {
  if (isOpen) document.addEventListener('keydown', onKeydown)
  else document.removeEventListener('keydown', onKeydown)
})

function onPointerDown(e: PointerEvent) {
  if (!root.value?.contains(e.target as Node)) close(false)
}

function onFocusOut(e: FocusEvent) {
  const next = e.relatedTarget as Node | null
  // Tabbing out of the menu closes it, so it never hides content behind it.
  if (next && !root.value?.contains(next)) close(false)
}

onMounted(() => document.addEventListener('pointerdown', onPointerDown))
onUnmounted(() => {
  document.removeEventListener('pointerdown', onPointerDown)
  document.removeEventListener('keydown', onKeydown)
})
</script>

<template>
  <div
    ref="root"
    class="relative"
    @focusout="onFocusOut"
  >
    <button
      ref="toggle"
      type="button"
      class="btn px-2"
      :aria-expanded="open"
      aria-controls="app-launcher"
      aria-label="Switch app"
      @click="onToggle"
    >
      <svg
        aria-hidden="true"
        viewBox="0 0 20 20"
        class="h-4 w-4"
        fill="currentColor"
      ><path d="M3 3h4v4H3zm5 0h4v4H8zm5 0h4v4h-4zM3 8h4v4H3zm5 0h4v4H8zm5 0h4v4h-4zM3 13h4v4H3zm5 0h4v4H8zm5 0h4v4h-4z" /></svg>
    </button>
    <nav
      v-show="open"
      id="app-launcher"
      aria-label="Apps"
      class="absolute left-0 mt-1 w-56 rounded-md border border-neutral-200 bg-white p-1 shadow-lg dark:border-neutral-800 dark:bg-neutral-900"
    >
      <ul>
        <li
          v-for="app in apps"
          :key="app.id"
        >
          <RouterLink
            :to="app.to"
            class="flex items-center justify-between rounded px-3 py-2 text-sm hover:bg-neutral-100 focus-visible:outline-2 focus-visible:outline-blue-600 dark:hover:bg-neutral-800"
            :class="app.id === current ? 'font-medium' : 'text-neutral-700 dark:text-neutral-300'"
            :aria-current="app.id === current ? 'page' : undefined"
            @click="open = false"
          >
            {{ app.label }}
            <span
              v-if="app.id === current"
              aria-hidden="true"
              class="text-blue-700 dark:text-blue-400"
            >&#10003;</span>
          </RouterLink>
        </li>
      </ul>
    </nav>
  </div>
</template>
