<script setup lang="ts">
import { buildFromMeta } from '@/lib/build'

/** Version and commit of the server build, on every page (fixed for the page's lifetime). */
const build = buildFromMeta()
</script>

<template>
  <footer
    v-if="build"
    class="px-4 py-2 text-center text-xs text-neutral-500 dark:text-neutral-400"
  >
    v{{ build.version }} · {{ build.commit }}
  </footer>
</template>
