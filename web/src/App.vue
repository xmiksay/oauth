<script setup lang="ts">
import BuildFooter from '@/components/BuildFooter.vue'
</script>

<template>
  <!-- Pages fill the screen above the footer (`flex-1`), so it sits at the bottom on every area. -->
  <div class="flex min-h-screen flex-col">
    <RouterView />
    <BuildFooter />
  </div>
</template>
