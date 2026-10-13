<script setup lang="ts" generic="T">
import { onMounted, useId } from 'vue'
import type { PagedList } from '@/composables/usePagedList'
import ErrorAlert from './ErrorAlert.vue'
import PagerControls from './PagerControls.vue'

/** Search box, error, empty state and pager around a paged list's table (default slot). */
const props = defineProps<{ list: PagedList<T>; searchLabel?: string; empty: string }>()
const searchId = useId()

onMounted(() => props.list.reload())
</script>

<template>
  <div>
    <div
      v-if="searchLabel"
      class="mb-3 max-w-sm"
    >
      <label
        :for="searchId"
        class="sr-only"
      >{{ searchLabel }}</label>
      <input
        :id="searchId"
        :value="list.search"
        type="search"
        class="input"
        :placeholder="searchLabel"
        @input="list.setSearch(($event.target as HTMLInputElement).value)"
      >
    </div>
    <ErrorAlert :error="list.error" />
    <div
      v-if="list.items.length"
      class="card overflow-x-auto p-0 sm:p-0"
    >
      <slot :items="list.items" />
    </div>
    <p
      v-else-if="!list.loading && !list.error"
      class="muted card text-sm"
    >
      {{ empty }}
    </p>
    <p
      v-if="list.loading"
      class="muted mt-2 text-sm"
      aria-live="polite"
    >
      Loading…
    </p>
    <PagerControls
      :page="list.page"
      :has-prev="list.hasPrev"
      :has-next="list.hasNext"
      :busy="list.loading"
      @prev="list.prev()"
      @next="list.next()"
    />
  </div>
</template>
