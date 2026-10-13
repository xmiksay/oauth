<script setup lang="ts">
import { onMounted, ref } from 'vue'

defineProps<{ locked: boolean }>()
const emit = defineEmits<{ submit: [email: string, password: string] }>()

const email = ref('')
const password = ref('')
const first = ref<HTMLInputElement | null>(null)
// Steps swap in place; move focus so keyboard and screen-reader users land on the new step.
onMounted(() => first.value?.focus())
</script>

<template>
  <form
    class="space-y-4"
    @submit.prevent="emit('submit', email.trim(), password)"
  >
    <div>
      <label
        class="label"
        for="login-email"
      >Email</label>
      <input
        id="login-email"
        ref="first"
        v-model="email"
        class="input"
        type="email"
        autocomplete="username"
        required
      >
    </div>
    <div>
      <label
        class="label"
        for="login-password"
      >Password</label>
      <input
        id="login-password"
        v-model="password"
        class="input"
        type="password"
        autocomplete="current-password"
        required
      >
    </div>
    <button
      type="submit"
      class="btn btn-primary w-full"
      :disabled="locked"
    >
      Sign in
    </button>
  </form>
</template>
