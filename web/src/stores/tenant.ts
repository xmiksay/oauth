import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useTenantStore = defineStore('tenant', () => {
  const slug = ref<string | null>(null)

  /** Accepts a raw route param (string | string[] | undefined) and normalises it. */
  function setFromParam(param: unknown) {
    slug.value = typeof param === 'string' && param.length > 0 ? param : null
  }

  return { slug, setFromParam }
})
