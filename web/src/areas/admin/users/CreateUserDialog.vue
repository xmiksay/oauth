<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { users, type CreatedUser } from '@/api/directory'
import { useAction } from '@/composables/useAction'
import { passwordProblem } from '@/lib/format'
import ModalDialog from '@/components/ModalDialog.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ close: []; created: [result: CreatedUser] }>()

const { me } = storeToRefs(useAuthStore())
const canInvite = computed(() => me.value?.features.email === true)

const email = ref('')
const displayName = ref('')
const invite = ref(false)
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
    invite.value = false
    setPassword.value = false
    password.value = ''
    mustChange.value = true
    error.value = null
  },
)

async function submit() {
  const inviting = invite.value && canInvite.value
  if (setPassword.value && !inviting) {
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
      ...(inviting
        ? { invite: true as const }
        : setPassword.value
          ? { password: password.value, must_change_password: mustChange.value }
          : {}),
    }),
  )
  password.value = ''
  if (res) emit('created', res)
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
      <label
        v-if="canInvite"
        class="flex items-center gap-2 text-sm"
      >
        <input
          v-model="invite"
          type="checkbox"
          data-testid="cu-invite"
        >
        Send an invitation email instead of setting a password
      </label>
      <label
        v-if="!invite"
        class="flex items-center gap-2 text-sm"
      >
        <input
          v-model="setPassword"
          type="checkbox"
        >
        Set the password myself (otherwise one is generated)
      </label>
      <p
        v-else
        class="hint"
      >
        The user chooses a password from the link we email them. It's valid for 7 days.
      </p>
      <template v-if="setPassword && !invite">
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
