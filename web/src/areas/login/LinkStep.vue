<script setup lang="ts">
import { computed } from 'vue'
import type { TxView } from '@/api/authn'
import PasswordStep from './PasswordStep.vue'

/**
 * An upstream identity the server couldn't match: the user signs in to their existing account
 * (password or passkey, then the usual MFA) and the server links the identity to it.
 */
const props = defineProps<{ link: NonNullable<TxView['link']>; locked: boolean; passkey: boolean }>()
const emit = defineEmits<{ submit: [email: string, password: string]; passkey: [] }>()

const idpName = computed(() => props.link.idp?.name ?? 'the identity provider')
</script>

<template>
  <div class="space-y-4">
    <p
      class="text-sm"
      data-testid="link-intro"
    >
      Sign in with your existing account to link {{ link.email ?? 'this identity' }} from
      {{ idpName }}. Next time you can sign in with {{ idpName }} directly.
    </p>
    <PasswordStep
      :locked="locked"
      :passkey="passkey"
      :initial-email="link.email ?? ''"
      @submit="(email, password) => emit('submit', email, password)"
      @passkey="emit('passkey')"
    />
  </div>
</template>
