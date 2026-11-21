<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import type { IdentityProvider, IdentityProviderInput, IdpKind } from '@/api/types'
import {
  CLIENT_AUTH_LABELS,
  POLICIES,
  POLICY_HELP,
  POLICY_LABELS,
  PRESETS,
  applyPreset,
  entraUrls,
  formState,
  isMultiTenant,
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
const isGithub = computed(() => f.kind === 'github')
const multiTenant = computed(() => isMultiTenant(f))
// GitHub's token endpoint always wants the secret: the server refuses an enabled GitHub
// provider without one.
const githubNeedsSecret = computed(
  () => isGithub.value && (props.initial ? props.initial.enabled : f.enabled),
)

function pickKind(event: Event) {
  applyPreset(f, (event.target as HTMLSelectElement).value as IdpKind)
  entraTenant.value = ''
}

// Entra helper (new providers): a directory id or organizations / common fills both URLs.
const entraTenant = ref('')
watch(entraTenant, (tenant) => {
  const urls = entraUrls(tenant)
  if (urls) Object.assign(f, urls)
})

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
      <div v-if="!initial">
        <label
          class="label"
          for="idp-kind"
        >Provider type</label>
        <select
          id="idp-kind"
          :value="f.kind"
          class="input"
          @change="pickKind"
        >
          <option
            v-for="(preset, kind) in PRESETS"
            :key="kind"
            :value="kind"
          >
            {{ preset.label }}
          </option>
        </select>
      </div>
      <p
        v-else
        class="text-sm"
      >
        <span class="font-medium">Provider type:</span> {{ PRESETS[f.kind].label }}
      </p>
      <div v-if="f.kind === 'entra' && !initial">
        <label
          class="label"
          for="idp-entra-tenant"
        >Directory (tenant) ID</label>
        <input
          id="idp-entra-tenant"
          v-model="entraTenant"
          class="input"
          placeholder="00000000-0000-0000-0000-000000000000, organizations or common"
        >
        <p class="hint">
          A directory ID makes it single-tenant; organizations or common accept any directory
          (multi-tenant). Fills in the issuer and discovery URL.
        </p>
      </div>
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
          required
        >
        <p
          v-if="isGithub"
          class="hint"
        >
          The web origin: https://github.com, or your GitHub Enterprise Server.
        </p>
        <p
          v-else-if="f.kind === 'entra'"
          class="hint"
        >
          {tenantid} in the issuer accepts tokens of any directory, checked against their tid.
        </p>
      </div>
      <div v-if="!isGithub">
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
          :required="githubNeedsSecret && !initial?.has_secret"
        >
        <p class="hint">
          Write-only: it is never shown again.
          <template v-if="isGithub">
            GitHub requires one: an enabled GitHub provider without a secret is refused.
          </template>
        </p>
        <label
          v-if="initial?.has_secret"
          class="mt-2 flex items-center gap-2 text-sm"
        >
          <input
            v-model="removeSecret"
            type="checkbox"
            :disabled="!!secret || githubNeedsSecret"
          >
          Remove the secret
        </label>
      </div>
      <div v-if="!isGithub">
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
          {{ isGithub ? 'Space-separated; user:email is needed for the email.' : 'Space-separated; openid is required.' }}
        </p>
      </div>
      <div v-if="f.kind === 'google'">
        <label
          class="label"
          for="idp-hd"
        >Hosted domain (optional)</label>
        <input
          id="idp-hd"
          v-model="f.hosted_domain"
          class="input"
          placeholder="contoso.com"
        >
        <p class="hint">
          Only accounts of this Google Workspace domain may sign in (the token's hd claim).
        </p>
      </div>
      <div v-if="multiTenant">
        <label
          class="label"
          for="idp-tenants"
        >Allowed directories (optional)</label>
        <input
          id="idp-tenants"
          v-model="f.allowed_tenants"
          class="input"
          placeholder="directory (tenant) IDs, comma-separated"
        >
        <p class="hint">
          Empty accepts every Entra directory.
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
      <div v-if="!isGithub">
        <label class="flex items-start gap-2 text-sm">
          <input
            id="idp-trust-email"
            v-model="f.trust_upstream_email"
            type="checkbox"
            class="mt-1"
          >
          <span>
            <span class="font-medium">Trust the provider's email addresses</span>
            <span class="muted block">Treat the email as verified even when the provider doesn't say
              so<template v-if="f.kind === 'entra'"> (Entra's xms_edov claim already counts)</template>.</span>
          </span>
        </label>
        <p
          v-if="f.trust_upstream_email"
          class="mt-1 text-sm text-amber-700 dark:text-amber-400"
          role="note"
        >
          Risk: new accounts get whatever address the provider reports. Only for a provider whose
          administrators control the addresses — never one where users type their own — and
          preferably limited to your email domains.
          <template v-if="multiTenant">
            A multi-tenant Entra provider must list its allowed tenants for this.
          </template>
        </p>
      </div>
      <div v-if="!isGithub">
        <label class="flex items-start gap-2 text-sm">
          <input
            id="idp-trust-mfa"
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
