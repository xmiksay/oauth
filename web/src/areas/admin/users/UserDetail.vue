<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { users } from '@/api/directory'
import type { UserDetail } from '@/api/types'
import { useAction } from '@/composables/useAction'
import { formatDate } from '@/lib/format'
import PageHeader from '@/components/PageHeader.vue'
import ErrorAlert from '@/components/ErrorAlert.vue'
import StatusNote from '@/components/StatusNote.vue'
import ConfirmButton from '@/components/ConfirmButton.vue'
import SecretOnceDialog from '@/components/SecretOnceDialog.vue'
import UserRoles from './UserRoles.vue'
import UserSessions from './UserSessions.vue'

const route = useRoute()
const router = useRouter()
const id = String(route.params.id)
const { canWriteUsers } = storeToRefs(useAuthStore())

const user = ref<UserDetail | null>(null)
const name = ref('')
const email = ref('')
const oneTime = ref<string[] | null>(null)
const loader = useAction()
const saver = useAction()
const saved = ref(false)
// Bumped after actions that end sessions so the sessions card reloads.
const sessionsVersion = ref(0)

async function load() {
  const u = await loader.run(() => users.get(id))
  if (!u) return
  user.value = u
  name.value = u.display_name
  email.value = u.email
}

onMounted(load)

async function save() {
  if (!user.value) return
  saved.value = false
  const body: { display_name?: string; email?: string } = {}
  if (name.value.trim() !== user.value.display_name) body.display_name = name.value.trim()
  if (email.value.trim() !== user.value.email) body.email = email.value.trim()
  if (await saver.run(() => users.update(id, body))) {
    saved.value = true
    await load()
  }
}

async function setDisabled(disabled: boolean) {
  await users.update(id, { disabled })
  sessionsVersion.value++
  await load()
}

async function resetPassword() {
  const res = await users.resetPassword(id)
  if (res.one_time_password) oneTime.value = [res.one_time_password]
  sessionsVersion.value++
  await load()
}

async function remove() {
  await users.remove(id)
  await router.replace({ name: 'admin-users' })
}

async function resetMfa() {
  await users.resetMfa(id)
  await load()
}

async function revokeSessions() {
  await users.revokeSessions(id)
  sessionsVersion.value++
}
</script>

<template>
  <section>
    <PageHeader
      :title="user?.display_name || user?.email || 'User'"
      :description="user?.email"
    >
      <template #breadcrumb>
        <RouterLink
          :to="{ name: 'admin-users' }"
          class="btn-link"
        >
          Users
        </RouterLink>
      </template>
    </PageHeader>
    <ErrorAlert :error="loader.error.value" />
    <template v-if="user">
      <p class="mb-4 flex flex-wrap gap-1">
        <span
          v-if="user.disabled"
          class="badge"
        >Disabled</span>
        <span
          v-if="user.must_change_password"
          class="badge"
        >Must change password</span>
        <span class="badge">MFA: {{ user.mfa.totp ? 'authenticator app' : 'none' }}</span>
        <span class="badge">{{ user.user_type }}</span>
      </p>
      <div
        v-if="canWriteUsers"
        class="mb-6 flex flex-wrap gap-2"
      >
        <ConfirmButton
          :label="user.disabled ? 'Enable' : 'Disable'"
          :title="user.disabled ? 'Enable user?' : 'Disable user?'"
          :message="
            user.disabled
              ? 'The user will be able to sign in again.'
              : 'The user can no longer sign in; their sessions end and refresh tokens are revoked.'
          "
          :danger="!user.disabled"
          :action="() => setDisabled(!user?.disabled)"
        />
        <ConfirmButton
          label="Reset password"
          title="Reset password?"
          message="A new temporary password is generated and shown once. All of the user's sessions end."
          :action="resetPassword"
        />
        <ConfirmButton
          label="Reset MFA"
          title="Reset MFA?"
          message="The user's authenticator app and recovery codes are removed. They can set up a new one in My Account."
          :disabled="!user.mfa.totp && !user.mfa.totp_pending"
          :action="resetMfa"
        />
        <ConfirmButton
          label="Revoke sessions"
          title="Sign the user out everywhere?"
          message="All sessions end and refresh tokens are revoked. Already-issued JWT access tokens stay valid until they expire."
          :action="revokeSessions"
        />
        <ConfirmButton
          label="Delete"
          title="Delete user?"
          :message="`${user.email} and their sessions, memberships, roles and consents are deleted. This cannot be undone.`"
          danger
          :action="remove"
        />
      </div>
      <div class="grid gap-4 xl:grid-cols-2">
        <form
          class="card space-y-4"
          @submit.prevent="save"
          @input="saved = false"
        >
          <h2 class="font-semibold">
            Properties
          </h2>
          <div>
            <label
              class="label"
              for="ud-name"
            >Display name</label>
            <input
              id="ud-name"
              v-model="name"
              class="input"
              :disabled="!canWriteUsers"
              required
            >
          </div>
          <div>
            <label
              class="label"
              for="ud-email"
            >Email</label>
            <input
              id="ud-email"
              v-model="email"
              class="input"
              type="email"
              :disabled="!canWriteUsers"
              required
            >
          </div>
          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt class="muted">
              Object ID
            </dt>
            <dd class="mono">
              {{ user.id }}
            </dd>
            <dt class="muted">
              Created
            </dt>
            <dd>{{ formatDate(user.created_at) }}</dd>
            <dt class="muted">
              Recovery codes left
            </dt>
            <dd>{{ user.mfa.recovery_codes_remaining }}</dd>
          </dl>
          <ErrorAlert :error="saver.error.value" />
          <StatusNote :message="saved ? 'Saved.' : null" />
          <button
            v-if="canWriteUsers"
            type="submit"
            class="btn btn-primary"
            :disabled="saver.busy.value"
          >
            Save
          </button>
        </form>
        <UserRoles :user-id="id" />
      </div>
      <UserSessions
        :key="sessionsVersion"
        :user-id="id"
        class="mt-4"
      />
    </template>
    <SecretOnceDialog
      title="Temporary password"
      description="Give this password to the user. They must change it at their next sign-in."
      :values="oneTime"
      @close="oneTime = null"
    />
  </section>
</template>
