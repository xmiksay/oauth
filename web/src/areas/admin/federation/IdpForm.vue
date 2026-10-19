<script setup lang="ts">
import { reactive, ref } from 'vue'
import type { IdentityProvider, IdentityProviderInput } from '@/api/types'
import {
  CLIENT_AUTH_LABELS,
  POLICIES,
  POLICY_HELP,
  POLICY_LABELS,
  formState,
  toInput,
} from './idpForm'

/**
 * Create (no `initial`) or edit form of an identity provider; the submit button lives with the
 * parent (`form="<formId>"`). Enabling is a separate action once the provider exists.
 * Re-mount it after a save: its state (the typed secret included) is initialised only once.
 */
const props = defineProps<{ formId: string; initial?: IdentityProvider; readonly?: boolean }>()
const emit = defineEmits<{ submit: [body: IdentityProviderInput] }>()

const f = reactive(formState(props.initial))
// Write-only: lives only in this form, is sent once and goes with the component.
const secret = ref('')
const removeSecret = ref(false)

function submit() {
  const { enabled, ...rest } = toInput(f)
  const body: IdentityProviderInput = props.initial ? rest : { ...rest, enabled }
  if (secret.value) body.client_secret = secret.value
  else if (removeSecret.value) body.client_secret = null
  emit('submit', body)
}
</script>

<template>
  <form
    :id="formId"
    class="space-y-4"
    @submit.prevent="submit"
  >
    <fieldset
      class="space-y-4"
      :disabled="readonly"
    >
      <div>
        <label
          class="label"
          for="idp-name"
        >Name</label>
        <input
          id="idp-name"
          v-model="f.name"
          class="input"
          required
        >
        <p class="hint">
          Shown on the sign-in button: "Sign in with {{ f.name || 'name' }}".
        </p>
      </div>
      <div>
        <label
          class="label"
          for="idp-issuer"
        >Issuer</label>
        <input
          id="idp-issuer"
          v-model="f.issuer"
          class="input"
          type="url"
          required
        >
      </div>
      <div>
        <label
          class="label"
          for="idp-discovery"
        >Discovery URL (optional)</label>
        <input
          id="idp-discovery"
          v-model="f.discovery_url"
          class="input"
          type="url"
        >
        <p class="hint">
          Defaults to the issuer's /.well-known/openid-configuration.
        </p>
      </div>
      <div>
        <label
          class="label"
          for="idp-client-id"
        >Client ID</label>
        <input
          id="idp-client-id"
          v-model="f.client_id"
          class="input"
          required
        >
      </div>
      <div v-if="!readonly">
        <label
          class="label"
          for="idp-secret"
        >{{ initial ? 'New client secret' : 'Client secret' }}</label>
        <input
          id="idp-secret"
          v-model="secret"
          class="input"
          type="password"
          autocomplete="off"
          :placeholder="initial?.has_secret ? 'Leave empty to keep the current secret' : ''"
        >
        <p class="hint">
          Write-only: it is never shown again.
        </p>
        <label
          v-if="initial?.has_secret"
          class="mt-2 flex items-center gap-2 text-sm"
        >
          <input
            v-model="removeSecret"
            type="checkbox"
            :disabled="!!secret"
          >
          Remove the secret
        </label>
      </div>
      <div>
        <label
          class="label"
          for="idp-client-auth"
        >Client authentication</label>
        <select
          id="idp-client-auth"
          v-model="f.client_auth"
          class="input"
        >
          <option
            v-for="(label, value) in CLIENT_AUTH_LABELS"
            :key="value"
            :value="value"
          >
            {{ label }}
          </option>
        </select>
      </div>
      <div>
        <label
          class="label"
          for="idp-scopes"
        >Scopes</label>
        <input
          id="idp-scopes"
          v-model="f.scopes"
          class="input"
        >
        <p class="hint">
          Space-separated; openid is required.
        </p>
      </div>
      <div>
        <label
          class="label"
          for="idp-domains"
        >Email domains</label>
        <input
          id="idp-domains"
          v-model="f.email_domains"
          class="input"
          placeholder="contoso.com, fabrikam.com"
        >
        <p class="hint">
          Comma-separated. Typing an address of these domains at sign-in suggests this provider.
        </p>
      </div>
      <fieldset>
        <legend class="label">
          Sign-in policy
        </legend>
        <label
          v-for="p in POLICIES"
          :key="p"
          class="mt-1 flex items-start gap-2 text-sm"
        >
          <input
            v-model="f.policy"
            type="radio"
            name="idp-policy"
            :value="p"
            class="mt-1"
          >
          <span>
            <span class="font-medium">{{ POLICY_LABELS[p] }}</span>
            <span class="muted block">{{ POLICY_HELP[p] }}</span>
          </span>
        </label>
      </fieldset>
      <div>
        <label class="flex items-start gap-2 text-sm">
          <input
            v-model="f.trust_upstream_mfa"
            type="checkbox"
            class="mt-1"
          >
          <span>
            <span class="font-medium">Trust the provider's MFA</span>
            <span class="muted block">Skip local MFA when the provider reports MFA (amr contains
              mfa, or acr equals the value below)</span>
          </span>
        </label>
        <div
          v-if="f.trust_upstream_mfa"
          class="mt-2"
        >
          <label
            class="label"
            for="idp-acr"
          >MFA acr value (optional)</label>
          <input
            id="idp-acr"
            v-model="f.mfa_acr"
            class="input"
          >
        </div>
      </div>
      <label class="flex items-start gap-2 text-sm">
        <input
          v-model="f.visible"
          type="checkbox"
          class="mt-1"
        >
        <span>
          <span class="font-medium">Show on the sign-in page</span>
          <span class="muted block">A hidden provider is still offered for its email domains and
            to apps that ask for it.</span>
        </span>
      </label>
      <label
        v-if="!initial"
        class="flex items-center gap-2 text-sm"
      >
        <input
          v-model="f.enabled"
          type="checkbox"
        >
        <span class="font-medium">Enabled</span>
      </label>
    </fieldset>
  </form>
</template>
