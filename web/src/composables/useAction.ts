import { ref } from 'vue'

/** Busy / error state around one async action (a form submit, a load). */
export function useAction() {
  const busy = ref(false)
  const error = ref<unknown>(null)

  async function run<T>(fn: () => Promise<T>): Promise<T | undefined> {
    busy.value = true
    error.value = null
    try {
      return await fn()
    } catch (err) {
      error.value = err
      return undefined
    } finally {
      busy.value = false
    }
  }

  return { busy, error, run }
}
