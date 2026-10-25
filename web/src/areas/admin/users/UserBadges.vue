<script setup lang="ts">
import type { UserDetail } from '@/api/types'

/** Status and MFA summary of a user as a row of badges. */
defineProps<{ user: UserDetail }>()
</script>

<template>
  <p class="flex flex-wrap gap-1">
    <span
      v-if="user.disabled"
      class="badge"
    >Disabled</span>
    <span
      v-if="user.must_change_password"
      class="badge"
    >Must change password</span>
    <span
      v-if="!user.has_password"
      class="badge"
    >{{ user.mfa.passkeys ? 'Passkey only' : 'No password yet' }}</span>
    <span class="badge">{{ user.email_verified ? 'Email verified' : 'Email unverified' }}</span>
    <span class="badge">MFA: {{ user.mfa.totp ? 'authenticator app' : 'none' }}</span>
    <span
      v-if="user.mfa.passkeys"
      class="badge"
    >Passkeys: {{ user.mfa.passkeys }}</span>
    <span
      v-if="user.mfa.telegram"
      class="badge"
    >Telegram linked</span>
    <span class="badge">{{ user.user_type }}</span>
  </p>
</template>
