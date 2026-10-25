<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import AppLauncher from './AppLauncher.vue'

/** Top bar shared by the portal, the admin center and My Account. */
defineProps<{ title: string; tenant: string | null; menuButton?: boolean; menuOpen?: boolean }>()
const emit = defineEmits<{ toggleMenu: [] }>()

const auth = useAuthStore()
const { me } = storeToRefs(auth)

async function signOut() {
  try {
    await auth.signOut()
  } catch {
    // No usable id_token (or discovery failed): the confirmation page signs out by cookie.
    window.location.assign('/logout')
  }
}
</script>

<template>
  <header
    class="sticky top-0 z-(--z-header) flex h-12 items-center gap-3 border-b border-neutral-200 bg-white px-3 sm:px-4 dark:border-neutral-800 dark:bg-neutral-900"
  >
    <button
      v-if="menuButton"
      type="button"
      class="btn px-2 md:hidden"
      :aria-expanded="menuOpen"
      aria-controls="side-nav"
      aria-label="Toggle navigation"
      @click="emit('toggleMenu')"
    >
      <svg
        aria-hidden="true"
        viewBox="0 0 20 20"
        class="h-4 w-4"
        fill="currentColor"
      ><path d="M3 5h14v2H3zm0 4h14v2H3zm0 4h14v2H3z" /></svg>
    </button>
    <AppLauncher />
    <span class="font-semibold">{{ title }}</span>
    <span class="hidden truncate text-sm text-neutral-500 sm:inline dark:text-neutral-400">{{
      tenant
    }}</span>
    <div class="ml-auto flex items-center gap-3">
      <span
        v-if="me"
        class="hidden max-w-48 truncate text-sm sm:inline"
        :title="me.email"
      >{{ me.display_name || me.email }}</span>
      <button
        type="button"
        class="btn"
        @click="signOut"
      >
        Sign out
      </button>
    </div>
  </header>
</template>
