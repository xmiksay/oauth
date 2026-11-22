// Application shapes of docs/api/management.md (re-exported by `types.ts`).
import type { AppMfaPolicy } from './types'

export type ClientType = 'confidential' | 'public'
export type TokenFormat = 'jwt' | 'opaque'
export type SigningAlg = 'RS256' | 'ES256'
/** What the `groups` claim of tokens for an app (as a resource) carries. */
export type GroupsClaimFormat = 'id' | 'name'

export interface Application {
  id: string
  client_id: string
  display_name: string
  client_type: ClientType
  builtin: boolean
  redirect_uris: string[]
  post_logout_redirect_uris: string[]
  /** Explicit CORS origins. */
  web_origins: string[]
  /** Read-only: web_origins plus, for public clients, the redirect URIs' origins. */
  effective_web_origins: string[]
  identifier_uri: string | null
  audience: string
  access_token_format: TokenFormat
  signing_alg: SigningAlg
  groups_claim_format: GroupsClaimFormat
  /** Only principals holding one of the app's roles get tokens to / for it. */
  assignment_required: boolean
  access_token_ttl_secs: number
  refresh_token_ttl_secs: number
  /** Opt-in to the device authorization grant (RFC 8628). */
  device_code_enabled: boolean
  /** `required`: signing in to this app (as client or requested resource) needs MFA. */
  mfa_policy: AppMfaPolicy
  /** OIDC Back-Channel Logout: where signed logout tokens are POSTed. */
  backchannel_logout_uri: string | null
  backchannel_logout_session_required: boolean
  created_at: string
  updated_at: string
}

export interface ApplicationCreate {
  display_name: string
  client_id?: string
  client_type?: ClientType
  redirect_uris?: string[]
}

export type ApplicationPatch = Partial<
  Pick<
    Application,
    | 'display_name'
    | 'redirect_uris'
    | 'post_logout_redirect_uris'
    | 'web_origins'
    | 'identifier_uri'
    | 'access_token_format'
    | 'signing_alg'
    | 'groups_claim_format'
    | 'assignment_required'
    | 'access_token_ttl_secs'
    | 'refresh_token_ttl_secs'
    | 'device_code_enabled'
    | 'mfa_policy'
    | 'backchannel_logout_uri'
    | 'backchannel_logout_session_required'
  >
>

export interface ClientSecret {
  id: string
  hint: string
  description: string | null
  expires_at: string
  created_at: string
}
