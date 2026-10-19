// Form state of an identity provider and the request bodies built from it.
import type {
  IdentityProvider,
  IdentityProviderInput,
  IdentityProviderPatch,
  IdpClientAuth,
  IdpPolicy,
} from '@/api/types'

export const POLICIES: IdpPolicy[] = ['link_only', 'jit', 'deny']

export const POLICY_LABELS: Record<IdpPolicy, string> = {
  jit: 'Create accounts',
  link_only: 'Link existing accounts',
  deny: 'Linked identities only',
}

export const POLICY_HELP: Record<IdpPolicy, string> = {
  jit: 'Create an account on first sign-in (needs a verified email; never links to an existing account)',
  link_only: 'Unknown identities must sign in with an existing account once to link it',
  deny: 'Only identities already linked may sign in',
}

export const CLIENT_AUTH_LABELS: Record<IdpClientAuth, string> = {
  post: 'In the request body (client_secret_post)',
  basic: 'HTTP Basic (client_secret_basic)',
}

const DEFAULT_SCOPES = ['openid', 'email', 'profile']

/** Editable fields as the inputs hold them (lists as text); the secret is kept apart. */
export interface IdpFormState {
  name: string
  issuer: string
  discovery_url: string
  client_id: string
  client_auth: IdpClientAuth
  scopes: string
  policy: IdpPolicy
  trust_upstream_mfa: boolean
  mfa_acr: string
  email_domains: string
  enabled: boolean
  visible: boolean
}

/** A new provider's defaults (those the server applies too), or `idp`'s current values. */
export function formState(idp?: IdentityProvider): IdpFormState {
  return {
    name: idp?.name ?? '',
    issuer: idp?.issuer ?? '',
    discovery_url: idp?.discovery_url ?? '',
    client_id: idp?.client_id ?? '',
    client_auth: idp?.client_auth ?? 'post',
    scopes: (idp?.scopes ?? DEFAULT_SCOPES).join(' '),
    policy: idp?.policy ?? 'link_only',
    trust_upstream_mfa: idp?.trust_upstream_mfa ?? false,
    mfa_acr: idp?.mfa_acr ?? '',
    email_domains: (idp?.email_domains ?? []).join(', '),
    enabled: idp?.enabled ?? true,
    visible: idp?.visible ?? true,
  }
}

/** Items of a comma- / whitespace-separated list. */
export function words(text: string): string[] {
  return text.split(/[\s,]+/).filter((w) => w.length > 0)
}

const orNull = (s: string) => s.trim() || null

export function toInput(f: IdpFormState): IdentityProviderInput {
  return {
    name: f.name.trim(),
    issuer: f.issuer.trim(),
    discovery_url: orNull(f.discovery_url),
    client_id: f.client_id.trim(),
    client_auth: f.client_auth,
    scopes: words(f.scopes),
    policy: f.policy,
    trust_upstream_mfa: f.trust_upstream_mfa,
    mfa_acr: orNull(f.mfa_acr),
    email_domains: words(f.email_domains),
    enabled: f.enabled,
    visible: f.visible,
  }
}

/** The fields of `input` that differ from `idp`; `client_secret` is write-only, so it always counts. */
export function changedIdpFields(
  idp: IdentityProvider,
  input: IdentityProviderPatch,
): IdentityProviderPatch {
  return Object.fromEntries(
    Object.entries(input).filter(
      ([key, value]) =>
        key === 'client_secret' ||
        JSON.stringify(value) !== JSON.stringify(idp[key as keyof IdentityProvider]),
    ),
  )
}

/**
 * Confirmation text when a save repoints the provider (issuer, client ID or
 * discovery URL): the server then unlinks every linked user and, when the
 * issuer or discovery URL moves without a new secret, drops the stored one.
 */
export function relinkWarning(
  diff: IdentityProviderPatch,
  linkedUsers: number,
  hasSecret = false,
): string | null {
  const repoint =
    diff.issuer !== undefined || diff.client_id !== undefined || diff.discovery_url !== undefined
  if (!repoint) return null
  const moved = diff.issuer !== undefined || diff.discovery_url !== undefined
  const newSecret = typeof diff.client_secret === 'string' && diff.client_secret !== ''
  const parts: string[] = []
  if (linkedUsers > 0) {
    const who = linkedUsers === 1 ? 'the 1 linked user' : `all ${linkedUsers} linked users`
    parts.push(
      `Changing the issuer, client ID or discovery URL unlinks ${who}; they must link again.`,
    )
  }
  if (moved && hasSecret && !newSecret) {
    parts.push('The stored client secret is removed too; enter the secret for the new provider.')
  }
  return parts.length ? parts.join(' ') : null
}

/** The lockout sentence for disabling / deleting a provider some users depend on. */
export function lockoutWarning(usersOnlyVia: number): string | null {
  if (usersOnlyVia <= 0) return null
  const who = usersOnlyVia === 1 ? '1 user' : `${usersOnlyVia} users`
  return `${who} can sign in only through this provider. They will be locked out until an administrator resets their password or sends an invitation.`
}
