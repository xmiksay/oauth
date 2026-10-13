<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { PASSWORD_MIN, passwordProblem } from '@/lib/format'

defineProps<{ locked: boolean }>()
const emit = defineEmits<{ submit: [password: string] }>()

const password = ref('')
const confirm = ref('')
const problem = ref<string | null>(null)

function submit() {
  problem.value = passwordProblem(password.value, confirm.value)
  if (!problem.value) emit('submit', password.value)
}
const first = ref<HTMLInputElement | null>(null)
// Steps swap in place; move focus so keyboard and screen-reader users land on the new step.
onMounted(() => first.value?.focus())
</script>

<template>
  <form
    class="space-y-4"
    novalidate
    @submit.prevent="submit"
  >
    <p class="muted text-sm">
      You need to choose a new password before you continue. Signing in with it ends your other
      sessions.
    </p>
    <div>
      <label
        class="label"
        for="new-password"
      >New password</label>
      <input
        id="new-password"
        ref="first"
        v-model="password"
        class="input"
        type="password"
        autocomplete="new-password"
        aria-describedby="new-password-hint"
        required
      >
      <p
        id="new-password-hint"
        class="hint"
      >
        At least {{ PASSWORD_MIN }} characters, different from your current password.
      </p>
    </div>
    <div>
      <label
        class="label"
        for="confirm-password"
      >Confirm new password</label>
      <input
        id="confirm-password"
        v-model="confirm"
        class="input"
        type="password"
        autocomplete="new-password"
        required
      >
    </div>
    <p
      v-if="problem"
      role="alert"
      class="text-sm text-red-700 dark:text-red-400"
    >
      {{ problem }}
    </p>
    <button
      type="submit"
      class="btn btn-primary w-full"
      :disabled="locked"
    >
      Change password
    </button>
  </form>
</template>
