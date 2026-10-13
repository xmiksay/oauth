<script setup lang="ts">
import { ref, watch } from 'vue'
import { users } from '@/api/directory'
import { useAction } from '@/composables/useAction'
import { passwordProblem } from '@/lib/format'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ close: []; created: [oneTimePassword: string | null] }>()

const email = ref('')
const displayName = ref('')
const setPassword = ref(false)
const password = ref('')
const mustChange = ref(true)
const { busy, error, run } = useAction()

watch(
  () => props.open,
  (open) => {
    if (!open) return
    email.value = ''
    displayName.value = ''
    setPassword.value = false
    password.value = ''
    mustChange.value = true
    error.value = null
  },
)

async function submit() {
  if (setPassword.value) {
    const problem = passwordProblem(password.value)
    if (problem) {
      error.value = problem
      return
    }
  }
  const res = await run(() =>
    users.create({
      email: email.value.trim(),
      display_name: displayName.value.trim(),
      ...(setPassword.value
        ? { password: password.value, must_change_password: mustChange.value }
        : {}),
    }),
  )
  password.value = ''
  if (res) emit('created', res.one_time_password)
}
</script>

<template>
  <ModalDialog
    :open="open"
    title="New user"
    @close="emit('close')"
  >
    <form
      id="create-user"
      class="space-y-4"
      @submit.prevent="submit"
    >
      <div>
        <label
          class="label"
          for="cu-email"
        >Email</label>
        <input
          id="cu-email"
          v-model="email"
          class="input"
          type="email"
          required
        >
      </div>
      <div>
        <label
          class="label"
          for="cu-name"
        >Display name</label>
        <input
          id="cu-name"
          v-model="displayName"
          class="input"
          required
        >
      </div>
      <label class="flex items-center gap-2 text-sm">
        <input
          v-model="setPassword"
          type="checkbox"
        >
        Set the password myself (otherwise one is generated)
      </label>
      <template v-if="setPassword">
        <div>
          <label
            class="label"
            for="cu-password"
          >Password</label>
          <input
            id="cu-password"
            v-model="password"
            class="input"
            type="password"
            autocomplete="new-password"
            required
          >
          <p class="hint">
            12–256 characters.
          </p>
        </div>
        <label class="flex items-center gap-2 text-sm">
          <input
            v-model="mustChange"
            type="checkbox"
          >
          Require a password change at first sign-in
        </label>
      </template>
      <ErrorAlert :error="error" />
    </form>
    <template #actions>
      <button
        type="button"
        class="btn"
        @click="emit('close')"
      >
        Cancel
      </button>
      <button
        type="submit"
        form="create-user"
        class="btn btn-primary"
        :disabled="busy"
      >
        Create
      </button>
    </template>
  </ModalDialog>
</template>
