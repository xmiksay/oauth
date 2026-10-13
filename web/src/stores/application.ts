import { defineStore, storeToRefs } from 'pinia'
import { computed, ref } from 'vue'
import { applications } from '@/api/applications'
import type { Application, ApplicationPatch } from '@/api/types'
import { useAuthStore } from './auth'

export function changedFields(app: Application, patch: ApplicationPatch): ApplicationPatch {
  return Object.fromEntries(
    Object.entries(patch).filter(
      ([key, value]) =>
        JSON.stringify(value) !== JSON.stringify(app[key as keyof ApplicationPatch]),
    ),
  )
}

/** The app registration open in the admin portal; shared by its detail tabs. */
export const useApplicationStore = defineStore('application', () => {
  const app = ref<Application | null>(null)
  const loading = ref(false)
  const error = ref<unknown>(null)
  const { canWriteApps, isGlobalAdmin } = storeToRefs(useAuthStore())

  /** Built-in apps are GlobalAdmin-only and accept only name / TTL changes. */
  const canEdit = computed(
    () => !!app.value && canWriteApps.value && (!app.value.builtin || isGlobalAdmin.value),
  )
  const canEditConfig = computed(() => canEdit.value && !app.value?.builtin)

  async function load(id: string) {
    if (app.value?.id !== id) app.value = null
    loading.value = true
    error.value = null
    try {
      app.value = await applications.get(id)
    } catch (err) {
      error.value = err
    } finally {
      loading.value = false
    }
  }

  /**
   * PATCHes the fields that differ from the open app; throws so forms can show the error.
   * Only changes are sent. The server also ignores values equal to the stored ones; this keeps
   * requests (and audit noise) minimal and doesn't depend on it.
   */
  async function update(patch: ApplicationPatch): Promise<Application> {
    const current = app.value
    if (!current) throw new Error('no application loaded')
    const diff = changedFields(current, patch)
    if (Object.keys(diff).length === 0) return current
    const updated = await applications.update(current.id, diff)
    app.value = updated
    return updated
  }

  return { app, loading, error, canEdit, canEditConfig, load, update }
})
